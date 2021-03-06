#include "pp.h"

volatile sig_atomic_t run;


static void __pp_set_action(struct pp_context *pp_ctx, enum pp_action action, char *packet_source);
static int __pp_run_pcap_file(struct pp_context *pp_ctx);
static int __pp_run_live_socket(struct pp_context *pp_ctx);
static int __pp_run_live_netfilter(struct pp_context *pp_ctx);
static enum PP_ANALYZER_ACTION __pp_packet_handler(struct pp_context *pp_ctx, enum PP_OSI_LAYERS first_layer, uint8_t *data, uint16_t len, uint64_t ts);
static void __pp_ctx_dump(struct pp_context *pp_ctx);
static int __rest_set_job_state(struct pp_context *pp_ctx, enum RestJobState state);
static int __pp_abort(struct pp_context *pp_ctx, char* msg);

static void* __pp_show_stats_thread(void *arg);
static void* __pp_report_thread(void *arg);
static void* __pp_flowtop_thread(void *arg);

/* context of the packet processor */
static struct pp_context pp_ctx;

int main(int argc, char **argv) {

	int rc = 0;

	signal(SIGINT, &pp_catch_term);
	signal(SIGQUIT, &pp_catch_term);
	signal(SIGTERM, &pp_catch_term);
	signal(SIGUSR1, &pp_catch_sigusr1);
	signal(SIGUSR2, &pp_catch_sigusr2);

	run = 1;

	if(pp_ctx_init(&pp_ctx, &__pp_packet_handler)) {
		fprintf(stderr, "failed to init packet processor. abort.\n");
		return 1;
	}

	if(pp_parse_cmd_line(argc, argv, &pp_ctx)) {
		pp_ctx_cleanup(&pp_ctx);
		return 1;
	}

	if (pp_ctx.processing_options & PP_PROC_OPT_USE_NDPI ||
		pp_ctx.processing_options & PP_PROC_OPT_LIST_NDPI_PROTOS) {
		if (pp_ndpi_init(&pp_ctx)) {
			fprintf(stderr, "failed to init nDPI context. abort.\n");
			return 1;
		}
	}

	/* application filter needs nDPI ctx for init protocol ids */
	if (pp_ctx.processing_options & PP_PROC_OPT_USE_PACKET_FILTER) {
		if(pp_applictaion_filter_protocol_init(&pp_ctx)) {
			return 1;
		}
	}

	if (pp_ctx.processing_options & PP_PROC_OPT_USE_REST) {
		if (pp_ctx.job_id == NULL) {
			fprintf(stderr,"REST requires job-id.\n");
			return 1; // Or maybe just generate a new ID
		}
	}

	if (pp_ctx.processing_options & PP_PROC_OPT_LIST_NDPI_PROTOS) {

		char **list = NULL;
		int c = 0, i = 0;

		if (0 > (c = pp_ndpi_get_protocol_list(&pp_ctx, &list))) {
			fprintf(stderr, "failed to get nDPI protocol list. abort.\n");
			return 1;
		}

		if (c == 0) {
			printf("nDPI protocol list is empty.\n");
			return 0;
		}

		for (i = 0; i < c; i++) {
			printf("%03d %s\n", i, list[i]);
		}
		free(list);

		return 0;
	}

	if(pthread_create(&pp_ctx.pt_stats, NULL, &__pp_show_stats_thread, &pp_ctx)) {
		fprintf(stderr, "failed to create show stats thread. abort.\n");
		return 1;
	}

	if(pthread_create(&pp_ctx.pt_report, NULL, &__pp_report_thread, &pp_ctx)) {
		fprintf(stderr, "failed to create report thread. abort.\n");
		return 1;
	}

	if (pp_ctx.processing_options & PP_PROC_OPT_SHOW_FLOWTOP) {
		if (pp_flowtop_init(&pp_ctx)) {
			fprintf(stderr, "failed to init flowtop environment. abort.\n");
			return 1;
		}
		if(pthread_create(&pp_ctx.pt_flowtop, NULL, &__pp_flowtop_thread, &pp_ctx)) {
			fprintf(stderr, "failed to create flowtop thread. abort.\n");
			return 1;
		}
	}

	switch(pp_ctx.action) {
		case PP_ACTION_CHECK:
			rc = pp_check_file(&pp_ctx);
			break;
		case PP_ACTION_ANALYZE_FILE:
			if(pp_pcap_open(&pp_ctx)) {
				rc = 1;
			} else {
				rc = __pp_run_pcap_file(&pp_ctx);
			}
			pp_pcap_close(&pp_ctx);
			break;
		case PP_ACTION_ANALYZE_LIVE_PF_SOCKET:
			rc = __pp_run_live_socket(&pp_ctx);
			break;
		case PP_ACTION_ANALYZE_LIVE_NETFILTER:
			rc = __pp_run_live_netfilter(&pp_ctx);
			break;
		default:
			rc = __pp_abort(&pp_ctx, "unknown action specified. abort.\n");
	}

	if (pp_ctx.processing_options & PP_PROC_OPT_SHOW_FLOWTOP) {
		pp_flowtop_destroy();
	}

	run = 0;

	/* dump selected stats on exit */
	pthread_cond_signal(&pp_ctx.pc_stats);
	//pthread_yield();
	do {
		usleep(100000);
	} while(0 != pthread_mutex_trylock(&pp_ctx.pm_stats));

	/* trigger report on exit */
	pthread_cond_signal(&pp_ctx.pc_report);
	//pthread_yield();
	do {
		usleep(100000);
	} while(0 != pthread_mutex_trylock(&pp_ctx.pm_report));

	pp_ctx_cleanup(&pp_ctx);

	return rc;
}

static void* __pp_show_stats_thread(void *arg) {

	struct pp_context *pp_ctx = arg;
	assert(arg);

	while(run) {

		pthread_mutex_lock(&pp_ctx->pm_stats);
		pthread_cond_wait(&pp_ctx->pc_stats, &pp_ctx->pm_stats);

		if (pp_ctx->processing_options & PP_PROC_OPT_DUMP_FLOWS) {
			pp_flow_table_dump(pp_ctx->flow_table);
		}

		if (pp_ctx->processing_options & PP_PROC_OPT_DUMP_TABLE_STATS) {
			pp_flow_table_stats(pp_ctx->flow_table);
		}

		if (pp_ctx->processing_options & PP_PROC_OPT_DUMP_PP_STATS ) {
			__pp_ctx_dump(pp_ctx);
		}

		if (pp_ctx->processing_options & PP_PROC_OPT_DUMP_NDPI_STATS) {
			pp_ndpi_stats_dump(pp_ctx);
		}

		if (pp_ctx->processing_options & PP_PROC_OPT_DUMP_APP_FILTER_STATS) {
			pp_application_filter_status_dump();
		}

		pthread_mutex_unlock(&pp_ctx->pm_stats);
	}

	return NULL;
}

static void* __pp_report_thread(void *arg) {

	struct pp_context *pp_ctx = arg;
	int b = 0;
	struct pp_flow *flow = NULL;
	char *report_data = NULL;
	int sample_id = 0;
	struct pp_analyzer *analyzer = NULL;

	assert(arg);

	while(run) {
		pthread_mutex_lock(&pp_ctx->pm_report);
		pthread_cond_wait(&pp_ctx->pc_report, &pp_ctx->pm_report);

		sample_id++;

		/* report */
		for (b = 0; b < pp_ctx->flow_table->size; b++) {
			if (pp_ctx->flow_table->buckets[b] != NULL) {
				flow = pp_ctx->flow_table->buckets[b];

				// add flow via REST (in the report thread to avoid blocking)
				if (pp_ctx->processing_options & PP_PROC_OPT_USE_REST && pp_ctx->job_id) {
					pp_rest_add_flow(pp_ctx->rest_backend_url, pp_ctx->job_id, flow);
				}

				do {

					pthread_mutex_lock(&flow->lock);

					analyzer = pp_ctx->analyzers;
					while (analyzer) {

						if (analyzer->report) {

							if (analyzer->analyze) {
								analyzer->analyze(analyzer->idx, flow);
							}

							report_data = analyzer->report(analyzer->idx, flow);
							if (report_data) {

								if (pp_ctx->processing_options & PP_PROC_OPT_USE_REST && pp_ctx->job_id) {
									if (pp_rest_post_analyze_data(pp_ctx->rest_backend_url,
									                              pp_ctx->job_id,
									                              analyzer->id(),
									                              flow->id,
									                              sample_id,
									                              report_data)) {
										fprintf(stderr, "REST communication error.\n");
									}
								}

								if (pp_ctx->job_id) {
									printf("{job-id: \"%s\"}\n", pp_ctx->job_id);
								}

								printf("{flow-id: %d}\n", flow->id);
								printf("{sample-id: %d}\n", sample_id);

								printf("%s\n", report_data);
								free(report_data);
							}
						} /* __has_report_function */
						analyzer = analyzer->next_analyzer;
					} /* __loop_analyzers */

					pthread_mutex_unlock(&flow->lock);

					flow = flow->next_flow;
				} while (flow); /* __loop_flows */
			} /* __bucket_has_data */
		} /* __loop_flow_hash_table */

		pthread_mutex_unlock(&pp_ctx->pm_report);
	}

	return NULL;
}

static void* __pp_flowtop_thread(void *arg) {

	struct pp_context *pp_ctx = arg;
	uint32_t dt = 0;

	assert(arg);

	while(run) {

		if (!(dt % pp_ctx->flowtop_interval)) {
			pp_flowtop_draw(pp_ctx);
		} else {
			pp_flowtop_header_print(pp_ctx);
		}

		dt++;
		sleep(1);
	}

	return NULL;
}

/**
 * @brief add flow to flow list
 * @note linear list is used by flowtop to generate a sorted list
 * @param pp_ctx the pp context
 * @param flow_ctx the flow to add
 * @retval 0 on success
 * @retval 1 on error
 */
static int __pp_flow_list_add(struct pp_context *pp_ctx, struct pp_flow *flow_ctx) {

	struct pp_flow_list_entry *new_entry = calloc(1, sizeof(struct pp_flow_list_entry));

	if (unlikely(!new_entry)) {
		return 1;
	}

	new_entry->flow = flow_ctx;

	pthread_mutex_lock(&pp_ctx->flow_list_lock);
	pp_ctx->flow_list_size++;

	if (unlikely(!pp_ctx->flow_list.head)) { /* the first entry */

		pp_ctx->flow_list.head = pp_ctx->flow_list.tail = new_entry;

		pthread_mutex_unlock(&pp_ctx->flow_list_lock);
		return 0;

	} else {

		pp_ctx->flow_list.tail->next = new_entry;
		new_entry->prev = pp_ctx->flow_list.tail;
		pp_ctx->flow_list.tail = new_entry;

		pthread_mutex_unlock(&pp_ctx->flow_list_lock);
		return 0;

	}
}

/**
 * @brief central packet handler callback, invokes analyzers
 * @param pp_ctx holds the config of pp
 * @param first_layer the first layer in the given data
 * @param data of the packet
 * @param len number of bytes in the packet
 * @param timestamp the packet was received (usec)
 */
static enum PP_ANALYZER_ACTION __pp_packet_handler(struct pp_context *pp_ctx,
								enum PP_OSI_LAYERS first_layer,
								uint8_t *data,
								uint16_t len,
								uint64_t ts) {

	struct pp_packet_context pkt_ctx;
	struct pp_flow *flow = NULL;
	uint32_t is_new = 0;
	uint32_t a = 0;
	int rc = 0;
	enum PP_ANALYZER_ACTION req_action = PP_ANALYZER_ACTION_NONE;
	struct pp_analyzer *analyzer = NULL;

	if (pp_ctx->bp_filter && !bpf_filter(pp_ctx->bp_filter, data, len, len)) {

		pthread_mutex_lock(&pp_ctx->stats_lock);
		pp_ctx->packets_seen++;
		pp_ctx->bytes_seen += len;
		pthread_mutex_unlock(&pp_ctx->stats_lock);

		return PP_ANALYZER_ACTION_ERROR;
	}

	rc = pp_decap(first_layer, data, len, ts, &pkt_ctx, pp_ctx->bp_filter);
	switch(rc) {
	case PP_DECAP_OKAY:

		pthread_mutex_lock(&pp_ctx->flow_table_lock);

		/* get flow for current packet and updates flow local counter
		 * and the packet direction attribute of the packet context
		 */
		flow = pp_flow_table_get_flow(pp_ctx->flow_table,
									  &pkt_ctx, &is_new);

		pthread_mutex_unlock(&pp_ctx->flow_table_lock);

		if (likely(flow)) {

			pthread_mutex_lock(&flow->lock);

			if (unlikely(is_new)) {

				if(pp_attach_analyzers_to_flow(pp_ctx, flow)) {
					pthread_mutex_unlock(&flow->lock);
					/* TODO: error handling */
					return PP_ANALYZER_ACTION_ERROR;
				}

				/* add flow to flow list */
				if (__pp_flow_list_add(pp_ctx, flow)) {
					pthread_mutex_unlock(&flow->lock);
					/* TODO: error handling */
					return PP_ANALYZER_ACTION_ERROR;
				}

				/* attach ndpi if selected */
				if((pp_ctx->processing_options & PP_PROC_OPT_USE_NDPI) &&
					pp_ndpi_flow_attach(flow, &pkt_ctx)) {
					/* TODO: error handling */
					printf("failed to attach ndpi flow ctx\n");
					return PP_ANALYZER_ACTION_ERROR;
				}

			} /* __new_flow */

			/* run ndpi */
			if ( !flow->ndpi_shortcut && (pp_ctx->processing_options & PP_PROC_OPT_USE_NDPI) ) {
				flow->ndpi_protocol = (const u_int32_t)ndpi_detection_process_packet(pp_ctx->ndpi_ctx,
																					 flow->ndpi_flow_ctx,
																					 pkt_ctx.packet + pkt_ctx.offsets[PP_OSI_LAYER_3],
																					 pkt_ctx.protocols[PP_OSI_LAYER_3] == ETH_P_IP?pkt_ctx.l3_meta.ip.length:pkt_ctx.l3_meta.ipv6.length,
																					 pkt_ctx.timestamp / 1000,
																					 flow->ndpi_src,
																					 flow->ndpi_dst);

				/* avoid use of detection if protocol was detected or
				 * we were not able to detect anything within the first
				 * n packets
				 */
				if ( (flow->ndpi_protocol != NDPI_PROTOCOL_UNKNOWN) ||
					 (flow->protocols[PP_OSI_LAYER_4] == IPPROTO_TCP && flow->data_cum.packets > PP_TCP_NDPI_PACKET_LIMIT) ||
					 (flow->protocols[PP_OSI_LAYER_4] == IPPROTO_UDP && flow->data_cum.packets > PP_UDP_NDPI_PACKET_LIMIT) ) {
					flow->ndpi_shortcut = 1;
				}

			} /* __run_ndpi */

			/* run selected analyzers */
			analyzer = pp_ctx->analyzers;
			while (analyzer) {
				req_action |= analyzer->inspect(analyzer->idx, &pkt_ctx, flow);
				analyzer = analyzer->next_analyzer;
			}

			pthread_mutex_unlock(&flow->lock);

			/* debug output */
			if (pp_ctx->processing_options & PP_PROC_OPT_DUMP_EACH_PACKET) {
				pp_dump_packet(&pkt_ctx);
			}
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
		break;
#endif
	} /* __switch_decap_result */

	/* update stats */
	pthread_mutex_lock(&pp_ctx->stats_lock);
	pp_ctx->packets_seen++;
	pp_ctx->bytes_seen += len;
	pp_ctx->unique_flows += !!is_new;

	if (flow) {
		pp_ctx->packets_taken ++;
		pp_ctx->bytes_taken += len;

		if (pp_ctx->ndpi_protocol_stats) {
			pp_ctx->ndpi_protocol_stats[flow->ndpi_protocol].packets++;
			pp_ctx->ndpi_protocol_stats[flow->ndpi_protocol].bytes += len;
		}
	}

	pthread_mutex_unlock(&pp_ctx->stats_lock);

	return req_action;
}

/**
 * @brief communicate job state to REST backend
 * @param pp_ctx context to use
 * @param state to send
 * @retval 0 on success
 * @retval 1 on error
 */
static int __rest_set_job_state(struct pp_context *pp_ctx, enum RestJobState state) {
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
	return 0;
}

static int __pp_run_pcap_file(struct pp_context *pp_ctx) {

	const uint8_t *pkt = NULL;
	struct pcap_pkthdr hdr;

	if (__rest_set_job_state(pp_ctx, JOB_STATE_RUNNING)) return 1;

	while (run && (pkt = pcap_next(pp_ctx->pcap_handle, &hdr))) {
		if (hdr.caplen == hdr.len) {
			pp_ctx->packet_handler_cb(pp_ctx,
									  PP_OSI_LAYER_2,
									  (uint8_t*)pkt, hdr.caplen,
									  (hdr.ts.tv_sec * 1000000) + (hdr.ts.tv_usec));
		}
	}

	__rest_set_job_state(pp_ctx, JOB_STATE_FINISHED); /* TODO: maybe find a better place */

	return 0;
}

static int __pp_run_live_socket(struct pp_context *pp_ctx) {

	int rc = 0;

	switch(pp_live_socket_init(pp_ctx)) {
		case EPERM:
			return __pp_abort(pp_ctx, "invalid permissions - failed to init live capture. abort.\n");
		case EINVAL:
			return __pp_abort(pp_ctx, "invalid configuration - failed to init live capture. abort.\n");
		case EBADF:
			return __pp_abort(pp_ctx, "error during network setup - failed to init live capture. abort.\n");
		case ENODEV:
			// TODO: send REST error message
			fprintf(stderr, "failed to access interface %s - failed to init live capture. abort.\n", pp_ctx->packet_source);
			return 1;
	}

	if (__rest_set_job_state(pp_ctx, JOB_STATE_RUNNING)) return 1;

	rc = pp_live_socket_capture(pp_ctx, &run);

	__rest_set_job_state(pp_ctx, JOB_STATE_FINISHED);

	pp_live_socket_shutdown(pp_ctx);

	return rc;
}

static int __pp_run_live_netfilter(struct pp_context *pp_ctx) {

	int rc = 0;

	switch(pp_live_netfilter_init(pp_ctx)) {
		case EPERM:
			fprintf(stderr, "invalid permissions - failed to init live capture. abort.\n");
			return 1;
		case EINVAL:
			fprintf(stderr, "invalid interface name given - failed to init live capture. abort.\n");
			return 1;
		case EBADF:
			fprintf(stderr, "error during network setup - failed to setup netfilter hook. abort.\n");
			return 1;
		case ENODEV:
			fprintf(stderr, "failed to access interface %s - failed to init live capture. abort.\n", pp_ctx->packet_source);
			return 1;
	}

	rc = pp_live_netfilter_capture(pp_ctx, &run);
	pp_live_netfilter_shutdown(pp_ctx);

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
int pp_parse_cmd_line(int argc, char **argv, struct pp_context *pp_ctx) {

	struct option options[] = {
		{"help", 0, NULL, 'h'},
		{"version", 0, NULL, 'v'},
		{"analyze", required_argument, NULL, 'a'},
		{"live-analyze-socket", required_argument, NULL, 'l'},
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
		{"dump-app-filter-stats", 0, NULL, 'S'},
		{"window-size-analyzer",0 , NULL, 'w'},
		{"analyze-infinity", 0, NULL, 'i'},
		{"analyze-timespan", required_argument, NULL, 't'},
		{"analyze-num-packets", required_argument, NULL, 'n'},
		{"flowtop", optional_argument, NULL, 'g'},
		{"use-ndpi", 0, NULL, 'D'},
		{"list-ndpi-protocols", 0, NULL, 'L'},
		{"dump-ndpi-stats", 0, NULL, 'N'},
		{"live-analyze-nf", optional_argument, NULL, 'z'},
		{"bandwidth-analyzer", 0, NULL, 'b'},
		{"rtt-analyzer", 0, NULL, 'q'},
		{"app-filter", required_argument, NULL, 'A'},
		{NULL, 0, NULL, 0}
	};
	int opt = 0, i = 0, rc = 0;
	char *endptr = NULL;
	uint32_t proto_id = 0;

	while(1) {
		opt = getopt_long(argc, argv, "hva:l:c:o:jf:J:r::PFTpwqit:n:g::DLNz::bA:S", options, NULL);
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
				__pp_set_action(pp_ctx, PP_ACTION_ANALYZE_FILE, optarg);
				break;
			case 'l':
				__pp_set_action(pp_ctx, PP_ACTION_ANALYZE_LIVE_PF_SOCKET, optarg);
				break;
			case 'z':
				if (optarg) {
					__pp_set_action(pp_ctx, PP_ACTION_ANALYZE_LIVE_NETFILTER, optarg);
				} else {
					__pp_set_action(pp_ctx, PP_ACTION_ANALYZE_LIVE_NETFILTER, "all");
				}
				pp_ctx->processing_options |= PP_PROC_OPT_CAN_DROP_PACKETS;
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
			case 'w': /* analyze window size */
				switch(pp_analyzer_register(&pp_ctx->analyzers,
									 &pp_window_size_inspect,
									 &pp_window_size_analyze,
									 &pp_window_size_report,
									 &pp_window_size_describe,
									 &pp_window_size_init,
									 &pp_window_size_destroy,
									 &pp_window_size_id,
									 NULL)) {
				case 0:
					pp_ctx->analyzer_num++;
					break;
				case ENOMEM:
					fprintf(stderr, "failed to register analyzer. abort.\n");
					exit(1);
				}
				break;
			 case 'q': /* analyze round trip time */
				switch(pp_analyzer_register(&pp_ctx->analyzers,
					             &pp_rtt_inspect,
					             &pp_rtt_analyze,
					             &pp_rtt_report,
					             &pp_rtt_describe,
					             &pp_rtt_init,
					             &pp_rtt_destroy,
					             &pp_rtt_id,
					                 NULL)) {
				case 0:
					pp_ctx->analyzer_num++;
					break;
				case ENOMEM:
					fprintf(stderr, "failed to register analyzer. abort.\n");
					exit(1);
				}
				break;
			case 'i':
				pp_ctx->analyzer_mode = PP_ANALYZER_MODE_INFINITY;
				break;
			case 't':
				pp_ctx->analyzer_mode = PP_ANALYZER_MODE_TIMESPAN;
				errno = 0;
				pp_ctx->analyzer_mode_val = strtol(optarg, NULL, 10);
				if (errno || pp_ctx->analyzer_mode_val < 1) {
					fprintf(stderr, "analyzer mode - given time span invalid.\nmust be at least 1 millisecond.\n");
					exit(1);
				}
				break;
			case 'n':
				pp_ctx->analyzer_mode = PP_ANALYZER_MODE_PACKETCOUNT;
				errno = 0;
				pp_ctx->analyzer_mode_val = strtol(optarg, NULL, 10);
				if (errno || pp_ctx->analyzer_mode_val < 1) {
					fprintf(stderr, "analyzer mode - given packet count invalid.\nmust be > 0.\n");
					exit(1);
				}
				break;
			case 'g':
				pp_ctx->processing_options |= PP_PROC_OPT_SHOW_FLOWTOP;
				if (optarg) {
					errno = 0;
					pp_ctx->flowtop_interval = strtol(optarg, NULL, 10);
					if (errno || pp_ctx->flowtop_interval < 1) {
						fprintf(stderr, "flowtop update interval must be > 1.\n");
						exit(1);
					}
				} else {
					pp_ctx->flowtop_interval = 5;
				}
				break;
			case 'D':
				pp_ctx->processing_options |= PP_PROC_OPT_USE_NDPI;
				break;
			case 'L':
				pp_ctx->processing_options |= PP_PROC_OPT_LIST_NDPI_PROTOS;
				/* shortcut - just list the protocols */
				return 0;
			case 'N':
				pp_ctx->processing_options |= PP_PROC_OPT_USE_NDPI;
				pp_ctx->processing_options |= PP_PROC_OPT_DUMP_NDPI_STATS;
				break;
			case 'b':
				switch(pp_analyzer_register(&pp_ctx->analyzers,
									 &pp_bandwidth_inspect,
									 &pp_bandwidth_analyze,
									 &pp_bandwidth_report,
									 &pp_bandwidth_describe,
									 &pp_bandwidth_init,
									 &pp_bandwidth_destroy,
									 &pp_bandwidth_id,
									 NULL)) {
				case 0:
					pp_ctx->analyzer_num++;
					break;
				case ENOMEM:
					fprintf(stderr, "failed to register analyzer. abort.\n");
					exit(1);
				}
				break;
			case 'A':
				switch(pp_analyzer_register(&pp_ctx->analyzers,
										 &pp_application_filter_inspect,
										 NULL,
										 NULL,
										 &pp_application_filter_describe,
										 &pp_application_filter_init,
										 &pp_application_filter_destroy,
										 &pp_application_filter_id,
										 NULL)) {
				case 0:
					pp_ctx->analyzer_num++;
					break;
				case ENOMEM:
					fprintf(stderr, "failed to register analyzer. abort.\n");
					exit(1);
				}
				pp_ctx->processing_options |= PP_PROC_OPT_USE_PACKET_FILTER;
				pp_ctx->processing_options |= PP_PROC_OPT_WILL_DROP_PACKETS;
				pp_ctx->processing_options |= PP_PROC_OPT_USE_NDPI;
				pp_application_filter_protocol_add(optarg);
				break;
			case 'S':
				pp_ctx->processing_options |= PP_PROC_OPT_DUMP_APP_FILTER_STATS;
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

	if ( !(pp_ctx->processing_options & PP_PROC_OPT_CAN_DROP_PACKETS) &&
		  (pp_ctx->processing_options & PP_PROC_OPT_WILL_DROP_PACKETS)) {
		fprintf(stderr, "selected analyzer needs drop packets capability - but selected packet source does not offer that kind functionality.\n");
		fprintf(stderr, "use packet source netfilter queue (--live-analyze-nf) or remove filter. abort.\n");
		return 1;
	}

	if (pp_ctx->analyzer_mode == PP_ANALYZER_MODE_PACKETCOUNT &&
		pp_ctx->analyzer_mode_val < WINDOWS_SIZE_ANALYZER_MIN_SAMPLE_COUNT) {
		fprintf(stderr, "configured analyzer packet count (=%d) < min sample count (=%d) for window size analyzer. abort.\n", pp_ctx->analyzer_mode_val, WINDOWS_SIZE_ANALYZER_MIN_SAMPLE_COUNT);
		return 1;
	}

	if ( !(pp_ctx->action & PP_ACTION_ANALYZE_LIVE_PF_SOCKET) &&
		 !(pp_ctx->action & PP_ACTION_ANALYZE_LIVE_NETFILTER) &&
		 (pp_ctx->processing_options & PP_PROC_OPT_SHOW_FLOWTOP)) {

		fprintf(stderr, "flowtop only available in live mode. abort.\n");
		return 1;
	}

	return 0;
}

/**
 * @brief handle signals requesting a dump of the current state
 * @param signal to handle
 */
void pp_catch_sigusr2(int sig) {

	if (0 != pthread_mutex_trylock(&pp_ctx.pm_stats)) {
		/* already running */
		return;
	}
	pthread_cond_signal(&pp_ctx.pc_stats);
}

/**
 * @brief handle signals requesting a report of the current analysis
 * @param signal to handle
 */
void pp_catch_sigusr1(int sig) {

	if (0 != pthread_mutex_trylock(&pp_ctx.pm_report)) {
		/* already running */
		return;
	}
	pthread_cond_signal(&pp_ctx.pc_report);
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
static void __pp_set_action(struct pp_context *pp_ctx, enum pp_action action, char *packet_source) {
	if (pp_ctx->action != PP_ACTION_UNDEFINED && pp_ctx->action != action) {
		fprintf(stderr, "more then one action requested but only one at a time supported. abort.\n");
		exit(1);
	}
	pp_ctx->action = action;
	free(pp_ctx->packet_source);
	if (!(pp_ctx->packet_source = strdup(packet_source))) {
		fprintf(stderr, "failed to alloc memory while setting action. abort.\n");
		exit(1);
	}
}

/**
 * @brief dump status data
 * @param pp_ctx point to the context to be dumped
 */
static void __pp_ctx_dump(struct pp_context *pp_ctx) {

	static char* analyzer_mode_str[PP_ANALYZER_MODE_EOL] = {
		[PP_ANALYZER_MODE_UNKNOWN] = "unknown",
		[PP_ANALYZER_MODE_INFINITY] = "infinity",
		[PP_ANALYZER_MODE_PACKETCOUNT] = "packet count",
		[PP_ANALYZER_MODE_TIMESPAN] = "timepspan"
	};

	pthread_mutex_lock(&pp_ctx->stats_lock);
	printf("-----------------------------------------\n");
	printf("unique flows:      %d\n", pp_ctx->unique_flows);
	printf("packets seen:      %" PRIu64 "\n", pp_ctx->packets_seen);
	printf("packets taken:     %" PRIu64 "\n", pp_ctx->packets_taken);
	printf("bytes seen:        %" PRIu64 "\n", pp_ctx->bytes_seen);
	printf("bytes taken:       %" PRIu64 "\n", pp_ctx->bytes_taken);
	printf("rest backend:      %s\n", pp_ctx->processing_options & PP_PROC_OPT_USE_REST?pp_ctx->rest_backend_url:"disabled");
	printf("analyzer mode:     %s\n", analyzer_mode_str[pp_ctx->analyzer_mode]);
	if (pp_ctx->analyzer_mode == PP_ANALYZER_MODE_PACKETCOUNT ||
		pp_ctx->analyzer_mode == PP_ANALYZER_MODE_TIMESPAN) {
		printf("analyzer mode val: %d\n", pp_ctx->analyzer_mode_val);
	}
	pthread_mutex_unlock(&pp_ctx->stats_lock);
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
	printf("-a --analyze <file>            analyze given pcap(ng) file\n");
	printf("-l --live-analyze-socket <iflist-ndpi-protocols>  capture and analyze traffic from \n");
	printf("                               given interface (may need root)\n");
	printf("-z --live-analyze-nf <if>      capture and analyze traffic from\n");
	printf("                               given interface (default: all),\n");
	printf("                               to handle all interfaces use name 'all'\n");
	printf("                               packets can be blocked by analyzers\n");
	printf("-f --bp-filter <bpf>           set Berkeley Packet Filter by given\n");
	printf("                               string (you may quote the string)\n");
	printf("\n");
	printf("-w --window-size-analyzer      analyze window size of detected flows\n");
	printf("-b --bandwidth-analyzer        analyze used bandwidth of dectected flows\n");
	printf("-q --rtt-analyzer              analyze round trip time\n");
	printf("-A --app-filter <app-name>     block application given by name\n");
	printf("                               can be used multible times\n");
	printf("                               use --list-ndpi-protocols to get a list\n");
	printf("                               of available protocol names\n");
	printf("\n");
	printf("-v --version                   show program version\n");
	printf("-h --help                      show help\n");
	printf("\n");
	printf("-o --output <file>             output to given file (default: stdout)\n");
	printf("                               for dumps requested while the analyzer\n");
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
	printf("-S --dump-app-filter-stats     dump application filter stats\n");
	printf("\n");
	printf("-i --analyze-infinite          analyze all packets (default)\n");
	printf("-t --analyze-timespan <num>    only analyze packets within the last\n");
	printf("                               <num> milliseconds\n");
	printf("-n --analyze-num-packets <num> only analyze last <num> packets\n");
	printf("\n");
	printf("-g --flowtop=<time>            show flowtop gui, set update interval to\n");
	printf("                               <time> seconds (default: 5)\n");
	printf("-D --use-ndpi                  use nDPI to classify protocols/applications\n");
	printf("                               (this will eat your memory and cpu)\n");
	printf("-L --list-ndpi-protocols       output a list of supported protocols\n");
	printf("-N --dump-ndpi-stats           dump protocol usage for nDPI protocols\n");
	printf("                               (activates use of nDPI implicitly)\n");
}

/**
 * @brief: print error, send error to REST and abort programm
 */
static int __pp_abort(struct pp_context *pp_ctx, char* msg) {
	fprintf(stderr, "%s", msg);
	if (pp_rest_job_state_msg(pp_ctx->rest_backend_url, pp_ctx->job_id, JOB_STATE_INTERNAL_ERROR, msg)) {
		fprintf(stderr, "REST communication error.\n");
		return 1;
	}
	return 1;
}
