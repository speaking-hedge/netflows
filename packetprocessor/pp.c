#include "pp.h"

volatile int run;
volatile int dump;

static void __pp_set_action(struct pp_config *pp_ctx, enum pp_action action, char *packet_source);
static int __pp_run_pcap_file(struct pp_config *pp_ctx);
static int __pp_run_live(struct pp_config *pp_ctx);
static void __pp_packet_handler(struct pp_config *pp_ctx, uint8_t *data, uint16_t len, uint64_t ts);

int main(int argc, char **argv) {

	struct pp_config pp_ctx;
	int rc = 0;

	signal(SIGINT, &pp_catch_term);
	signal(SIGQUIT, &pp_catch_term);
	signal(SIGTERM, &pp_catch_term);

	signal(SIGUSR1, &pp_catch_dump);

	pp_init_ctx(&pp_ctx, &__pp_packet_handler);

	if(pp_parse_cmd_line(argc, argv, &pp_ctx)) {
		pp_cleanup_ctx(&pp_ctx);
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

	pp_cleanup_ctx(&pp_ctx);

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

	struct packet_context pkt_ctx;

	if(0 <= pp_decap(data, len, ts, &pkt_ctx)) {
		pp_dump_packet(&pkt_ctx);
	} else {
		printf(".");
		fflush(stdout);
	}
}

static int __pp_run_pcap_file(struct pp_config *pp_ctx) {

	const uint8_t *pkt = NULL;
	struct pcap_pkthdr hdr;

	run = 1;
	while (run && (pkt = pcap_next(pp_ctx->pcap_handle, &hdr))) {
		if (hdr.caplen == hdr.len) {
			pp_ctx->packet_handler_cb(pp_ctx, (uint8_t*)pkt, hdr.caplen, (hdr.ts.tv_sec * 1000) + (hdr.ts.tv_usec / 1000));
		}
	}
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
		{"analyse", 1, NULL, 'a'},
		{"live-analyse", 1, NULL, 'l'},
		{"check", 1, NULL, 'c'},
		{"output", 1, NULL, 'o'},
		{"gen-job-id", 0, NULL, 'j'},
		{NULL, 0, NULL, 0}
	};
	int opt = 0, i = 0;
	char *endptr = NULL;

    while(1) {
		opt = getopt_long(argc, argv, "hva:l:c:o:j", options, NULL);
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
void pp_catch_dump(int signal) {
	dump = 1;
}

/**
 * @brief handle signals requesting program to exit
 * @param signal to handle
 */
void pp_catch_term(int signal) {
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
	printf("-c --check <file>       do not process the file, just check if \n");
	printf("                        given file is a valid pcap(ng) file\n");
	printf("-j --gen-job-id         generate a unique job-id (sha256) based\n");
	printf("                        on given file\n");
	printf("-a --analyse <file>     analyse given pcap(ng) file\n");
	printf("-l --live-analyse <if>  capture and analyse traffic from given interface\n");
	printf("\n");
	printf("-v --version            show program version\n");
	printf("-h --help               show help\n");
	printf("\n");
	printf("-o --output <file>      output to given file (default: stdout)\n");
	printf("                        for dumps requested while the analyser\n");
	printf("                        is still running, an increasing nummber is\n");
	printf("                        appended to the filename\n");
}
