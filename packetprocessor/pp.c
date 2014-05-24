#include "pp.h"

volatile sig_atomic_t run;
volatile sig_atomic_t dump;

static void __pp_set_action(struct pp_config *pp_ctx, enum pp_action action, char *packet_source);
static int __pp_run_pcap_file(struct pp_config *pp_ctx);
static int __pp_run_live(struct pp_config *pp_ctx);
static void __pp_packet_handler(struct pp_config *pp_ctx, uint8_t *data, uint16_t len, uint64_t ts);
static void __pp_ctx_dump(struct pp_config *pp_ctx);

int main(int argc, char **argv) {

	struct pp_config pp_ctx;
	int rc = 0;

	signal(SIGINT, &pp_catch_term);
	signal(SIGQUIT, &pp_catch_term);
	signal(SIGTERM, &pp_catch_term);
	signal(SIGUSR1, &pp_catch_dump);

	if(pp_ctx_init(&pp_ctx, &__pp_packet_handler)) {
		fprintf(stderr, "failed to init packet processor. abort.\n");
		return 1;
	}

	if(pp_parse_cmd_line(argc, argv, &pp_ctx)) {
		pp_ctx_cleanup(&pp_ctx);
		return 1;
	}

	switch(pp_ctx.action) {
		case PP_ACTION_CHECK:
			rc = pp_check_file(&pp_ctx);
			break;
		case PP_ACTION_ANALYSE_FILE:
			if(pp_pcap_open(&pp_ctx)) {
				rc = 1;
			} else {
				rc = __pp_run_pcap_file(&pp_ctx);
			}
			pp_pcap_close(&pp_ctx);
			break;
		case PP_ACTION_ANALYSE_LIVE:
			rc = __pp_run_live(&pp_ctx);
			break;
		default:
			fprintf(stderr, "unknown action specified. abort.\n");
			rc = 1;
	}

	if (pp_ctx.processing_options & PP_PROC_OPT_DUMP_FLOWS)
		pp_flow_table_dump(pp_ctx.flow_table);
	if (pp_ctx.processing_options & PP_PROC_OPT_DUMP_TABLE_STATS)
		pp_flow_table_stats(pp_ctx.flow_table);
	if (pp_ctx.processing_options & PP_PROC_OPT_DUMP_PP_STATS)
		__pp_ctx_dump(&pp_ctx);

	pp_ctx_cleanup(&pp_ctx);

	return rc;
}

/**
 * @brief central packet handler callback, invokes analysers
 * @param pp_ctx holds the config of pp
 * @param data of the packet
 * @param len number of bytes in the packet
 * @param timestamp the packet was received
 */
static void __pp_packet_handler(struct pp_config *pp_ctx,
							uint8_t *data,
							uint16_t len,
							uint64_t ts) {

	struct pp_packet_context pkt_ctx;
	struct pp_flow *flow = NULL;
	int is_new = 0;
	int a = 0;

	pp_ctx->packets_seen++;
	pp_ctx->bytes_seen += len;

	if (pp_ctx->bp_filter && !bpf_filter(pp_ctx->bp_filter, data, len, len)) {
		return;
	}

	switch(pp_decap(data, len, ts, &pkt_ctx, pp_ctx->bp_filter)) {
	case PP_DECAP_OKAY:
		/* get flow for current packet and updates flow local counter
		 * and the packet direction attribute of the packet context
		 */
		flow = pp_flow_table_get_flow(pp_ctx->flow_table,
									  &pkt_ctx, &is_new);

		if (flow) {
			if (is_new) {
				pp_ctx->unique_flows++;

				/* attach and init analysers */
				if (!(flow->analyser_data = calloc(1, sizeof(void *)))) {
					/* TODO: error handling */
					return;
				}

				/* init flow local data for each analyser */
				for (a = 0; a < pp_ctx->pp_analyser_num; a++) {
					pp_ctx->pp_analysers[a].init(pp_ctx->pp_analysers[a].idx,
					                             flow,
					                             pp_ctx->analyser_mode,
					                             pp_ctx->analyser_mode_val);
				}

			}
			pp_ctx->packets_taken++;
			pp_ctx->bytes_taken += len;

			/* run selected analysers */
			for (a = 0; a < pp_ctx->pp_analyser_num; a++) {
				pp_ctx->pp_analysers[a].collect(pp_ctx->pp_analysers[a].idx, &pkt_ctx, flow);
			}

			if (pp_ctx->processing_options & PP_PROC_OPT_DUMP_EACH_PACKET)
				pp_dump_packet(&pkt_ctx);
		}
		break;
#ifdef PP_DEBUG
	case -PP_DECAP_L2_PROTO_UNKNOWN:
	case -PP_DECAP_L3_PROTO_UNKNOWN:
	case -PP_DECAP_L4_PROTO_UNKNOWN:
		printf("u"); fflush(stdout);
		break;
	case -PP_DECAP_L2_ERROR:
	case -PP_DECAP_L3_ERROR:
	case -PP_DECAP_L4_ERROR:
		printf("e"); fflush(stdout);
		break;
	default:
		printf("x"); fflush(stdout);
#endif
	}
}

static int __rest_set_job_state(struct pp_config *pp_ctx, enum RestJobState state) {
	if (pp_ctx->processing_options & PP_PROC_OPT_USE_REST) {
		if (pp_ctx->job_id == NULL) {
			fprintf(stderr,"REST requires job-id.\n");
			return 1;
		}
		if (pp_rest_job_state(pp_ctx->rest_backend_url, pp_ctx->job_id, state)) {
			fprintf(stderr, "REST communication error.\n");
			return 1;
		}
	}
}

static int __pp_run_pcap_file(struct pp_config *pp_ctx) {

	const uint8_t *pkt = NULL;
	struct pcap_pkthdr hdr;

	if (__rest_set_job_state(pp_ctx, JOB_STATE_RUNNING)) return 1;

	run = 1;
	while (run && (pkt = pcap_next(pp_ctx->pcap_handle, &hdr))) {
		if (hdr.caplen == hdr.len) {
			pp_ctx->packet_handler_cb(pp_ctx, (uint8_t*)pkt, hdr.caplen, (hdr.ts.tv_sec * 1000000) + (hdr.ts.tv_usec));
		}
		if (dump) {
			pp_dump_state(pp_ctx);
			dump = 0;
		}
	}

        __rest_set_job_state(pp_ctx, JOB_STATE_FINISHED); // maybe find a better place
}

static int __pp_run_live(struct pp_config *pp_ctx) {

	int rc = 0;

	switch(pp_live_init()) {
		case EPERM:
			fprintf(stderr, "invalid permissions - failed to init live capture. abort.\n");
			return 1;
		case EINVAL:
			fprintf(stderr, "invalid configuration - failed to init live capture. abort.\n");
			return 1;
		case EBADF:
			fprintf(stderr, "error during network setup - failed to init live capture. abort.\n");
			return 1;
		case ENODEV:
			fprintf(stderr, "failed to access interface %s - failed to init live capture. abort.\n", pp_ctx->packet_source);
			return 1;
	}

	run = 1;
	rc = pp_live_capture(pp_ctx, &run, &dump);
	pp_live_shutdown(pp_ctx);

	return rc;
}

/**
 * @brief parse command line options and set config in pp_ctx
 * @param argc as supplied to main
 * @param argv as supplied to main
 * @param ctx that holds the pp configuration
 * @retval 0 on success
 * @retval 1 on error
 */
int pp_parse_cmd_line(int argc, char **argv, struct pp_config *pp_ctx) {

	struct option options[] = {
		{"help", 0, NULL, 'h'},
		{"version", 0, NULL, 'v'},
		{"analyse", required_argument, NULL, 'a'},
		{"live-analyse", required_argument, NULL, 'l'},
		{"check", required_argument, NULL, 'c'},
		{"output", required_argument, NULL, 'o'},
		{"gen-job-id", 0, NULL, 'j'},
		{"job-id", required_argument, NULL, 'J'},
		{"bp-filter", required_argument, NULL, 'f'},
		{"rest-backend", optional_argument, NULL, 'r'},
		{"dump-packets", 0, NULL, 'P'},
		{"dump-flows", 0, NULL, 'F'},
		{"dump-table-stats", 0, NULL, 'T'},
		{"dump-packet-processor-stats", 0, NULL, 'p'},
		{"analyse-window-size",0 , NULL, 'w'},
		{"analyse-infinity", 0, NULL, 'i'},
		{"analyse-timespan", required_argument, NULL, 't'},
		{"analyse-num-packets", required_argument, NULL, 'n'},
		{NULL, 0, NULL, 0}
	};
	int opt = 0, i = 0;
	char *endptr = NULL;

	while(1) {
		opt = getopt_long(argc, argv, "hva:l:c:o:jf:J:r::PFTpwit:n:", options, NULL);
		if (opt == -1)
			break;

		switch(opt) {
			case '?':
				exit(1);
			case 'h':
				pp_usage();
				exit(0);
			case 'v':
				pp_version();
				exit(0);
			break;
			case 'a':
				__pp_set_action(pp_ctx, PP_ACTION_ANALYSE_FILE, optarg);
				break;
			case 'l':
				__pp_set_action(pp_ctx, PP_ACTION_ANALYSE_LIVE, optarg);
				break;
			case 'c':
				__pp_set_action(pp_ctx, PP_ACTION_CHECK, optarg);
				break;
			case 'o': /* output file */
				free(pp_ctx->output_file);
				if(!(pp_ctx->output_file = strdup(optarg))) {
					fprintf(stderr, "failed to alloc memory for output filename. abort.\n");
					exit(1);
				}
				break;
			case 'j': /* create hash */
				pp_ctx->processing_options |= PP_PROC_OPT_CREATE_HASH;
				break;
			case 'J': /* use id */
				free(pp_ctx->job_id);
				if (!(pp_ctx->job_id = strdup(optarg))) {
					fprintf(stderr, "failed to alloc memory for job-id. abort.\n");
					exit(1);
				}
				break;
			case 'f':
				if (pp_ctx->bp_filter) {
					fprintf(stderr, "more then one filter string given but only one allowed. abort.\n");
					exit(1);
				}
				struct bpf_program bpfp;
				if (pcap_compile_nopcap(1500,
										DLT_EN10MB,
										&bpfp,
										optarg, 1, 0)) {
					fprintf(stderr, "failed to compile packet filter. abort.\n");
					exit(1);
				}
				pp_ctx->bp_filter = bpfp.bf_insns;
				break;
			case 'P':
				pp_ctx->processing_options |= PP_PROC_OPT_DUMP_EACH_PACKET;
				break;
			case 'F':
				pp_ctx->processing_options |= PP_PROC_OPT_DUMP_FLOWS;
				break;
			case 'T':
				pp_ctx->processing_options |= PP_PROC_OPT_DUMP_TABLE_STATS;
				break;
			case 'p':
				pp_ctx->processing_options |= PP_PROC_OPT_DUMP_PP_STATS;
				break;
			case 'r':
				free(pp_ctx->rest_backend_url);
				if (!optarg) {
					if(!(pp_ctx->rest_backend_url = strdup("localhost:80"))) {
						fprintf(stderr, "failed to alloc memory for rest default url. abort.\n");
						exit(1);
					}
				} else {
					if(!(pp_ctx->rest_backend_url = strdup(optarg))) {
						fprintf(stderr, "failed to alloc memory for rest url. abort.\n");
						exit(1);
					}
				}
				pp_ctx->processing_options |= PP_PROC_OPT_USE_REST;
				break;
			case 'w': /* analyse window size */
				pp_register_analyser(&pp_ctx->pp_analysers,
									 &pp_window_size_collect,
									 &pp_window_size_analyse,
									 &pp_window_size_report,
									 &pp_window_size_describe,
									 &pp_window_size_init,
									 &pp_window_size_destroy,
									 NULL);
				pp_ctx->pp_analyser_num++;
				break;
			case 'i':
				pp_ctx->analyser_mode = PP_ANALYSER_MODE_INFINITY;
				break;
			case 't':
				pp_ctx->analyser_mode = PP_ANALYSER_MODE_TIMESPAN;
				errno = 0;
				pp_ctx->analyser_mode_val = strtol(optarg, NULL, 10);
				if (errno || pp_ctx->analyser_mode_val < 1) {
					fprintf(stderr, "analyser mode - given time span invalid.\nmust be at least 1 millisecond.\n");
					exit(1);
				}
				break;
			case 'n':
				pp_ctx->analyser_mode = PP_ANALYSER_MODE_PACKETCOUNT;
				errno = 0;
				pp_ctx->analyser_mode_val = strtol(optarg, NULL, 10);
				if (errno || pp_ctx->analyser_mode_val < 1) {
					fprintf(stderr, "analyser mode - given packet count invalid.\nmust be > 0.\n");
					exit(1);
				}
				break;
			default:
				abort();
		}
	}

	/* sanity checks */
	if (pp_ctx->action == PP_ACTION_UNDEFINED) {
		fprintf(stderr, "no action specified. abort.\n");
		return 1;
	}

	return 0;
}

/**
 * @brief handle signals requesting a dump of the current state
 * @param signal to handle
 */
void pp_catch_dump(int sig) {
	dump = 1;
}

/**
 * @brief handle signals requesting program to exit
 * @param signal to handle
 */
void pp_catch_term(int sig) {
	run = 0;
}

/**
 * @brief set action  and packet source checking there was no other action selected before
 * @param pp_ctx holds the config of pp
 * @param action that is requested
 * @param packet_source points to a file or a network interface name
 */
static void __pp_set_action(struct pp_config *pp_ctx, enum pp_action action, char *packet_source) {
	if (pp_ctx->action != PP_ACTION_UNDEFINED && pp_ctx->action != action) {
		fprintf(stderr, "more then one action requested but only one at a time supported. abort.\n");
		exit(1);
	}
	pp_ctx->action = action;
	free(pp_ctx->packet_source);
	if (!(pp_ctx->packet_source = strdup(optarg))) {
		fprintf(stderr, "failed to alloc memory while setting action. abort.\n");
		exit(1);
	}
}

/**
 * @brief dump status data
 * @param pp_ctx point to the context to be dumped
 */
static void __pp_ctx_dump(struct pp_config *pp_ctx) {

	static char* analyser_mode_str[PP_ANALYSER_MODE_EOL] = {
		[PP_ANALYSER_MODE_UNKNOWN] = "unknown",
		[PP_ANALYSER_MODE_INFINITY] = "infinity",
		[PP_ANALYSER_MODE_PACKETCOUNT] = "packet count",
		[PP_ANALYSER_MODE_TIMESPAN] = "timepspan"
	};

	printf("-----------------------------------------\n");
	printf("unique flows:      %d\n", pp_ctx->unique_flows);
	printf("packets seen:      %" PRIu64 "\n", pp_ctx->packets_seen);
	printf("packets taken:     %" PRIu64 "\n", pp_ctx->packets_taken);
	printf("byte seen:         %" PRIu64 "\n", pp_ctx->bytes_seen);
	printf("bytes taken:       %" PRIu64 "\n", pp_ctx->bytes_taken);
	printf("rest backend:      %s\n", pp_ctx->processing_options & PP_PROC_OPT_USE_REST?pp_ctx->rest_backend_url:"disabled");
	printf("analyser mode:     %s\n", analyser_mode_str[pp_ctx->analyser_mode]);
	if (pp_ctx->analyser_mode == PP_ANALYSER_MODE_PACKETCOUNT ||
		pp_ctx->analyser_mode == PP_ANALYSER_MODE_TIMESPAN) {
		printf("analyser mode val: %d\n", pp_ctx->analyser_mode_val);
	}
}

/**
 * @brief: show program version
 */
void pp_version(void) {
#ifdef PPSHA
	printf("version %s (build on %s)\n", PPVERSION, PPSHA);
#else
	printf("version %s\n", PPVERSION);
#endif
}

/**
 * @brief: output programs help text
 */
void pp_usage(void) {
	int i;
	printf("Usage: pp [OPTION] FILE\n");
	printf("processes network packets gathered from sniffed traffic to generate\n");
	printf("flow related statistics\n\n");
	printf("-c --check <file>              do not process the file, just check if \n");
	printf("                               given file is a valid pcap(ng) file\n");
	printf("-j --gen-job-id                generate a unique job-id (sha256) based\n");
	printf("                               on given file\n");
	printf("-J --job-id <id>               use given id <id> to identify\n");
	printf("                               generated reports\n");
	printf("-a --analyse <file>            analyse given pcap(ng) file\n");
	printf("-l --live-analyse <if>         capture and analyse traffic from \n");
	printf("                               given interface (may need root)\n");
	printf("-f --bp-filter <bpf>           set Berkeley Packet Filter by given\n");
	printf("                               string (you may quote the string)\n");
	printf("\n");
	printf("-v --version                   show program version\n");
	printf("-h --help                      show help\n");
	printf("\n");
	printf("-o --output <file>             output to given file (default: stdout)\n");
	printf("                               for dumps requested while the analyser\n");
	printf("                               is still running, an increasing nummber\n");
	printf("                               is appended to the filename\n");
	printf("\n");
	printf("-r<URL>                        use REST backend at given URL\n");
	printf("--rest-backend=<URL>           (default: localhost:80)\n");
	printf("\n");
	printf("-P --dump-packets              dump each packet (time consuming!)\n");
	printf("-F --dump-flows                dump all flows at exit\n");
	printf("-T --dump-table-stats          dump flow table stats at exit\n");
	printf("-p --dump-pp-stats             dump packet processor stats at exit\n");
	printf("\n");
	printf("-i --analyse-infinite          analyse all packets (default)\n");
	printf("-t --analyse-timespan <num>    only analyse packets within the last\n");
	printf("                               <num> milliseconds\n");
	printf("-n --analyse-num-packets <num> only analyse last <num> packets\n");
}
