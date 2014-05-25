#ifndef __PP_CONTEXT
#define __PP_CONTEXT

#include <pthread.h>
#include <pp_analyzer.h>
#include <pp_flow.h>


struct pp_context {

	enum pp_action {
		PP_ACTION_UNDEFINED,
		PP_ACTION_ANALYZE_FILE,
		PP_ACTION_ANALYZE_LIVE,
		PP_ACTION_CHECK
	} action;

	char *packet_source;
	char *output_file;

	char *job_id;

	pcap_t *pcap_handle;
	int packet_socket;

	void (*packet_handler_cb)(struct pp_context *pp_ctx, uint8_t *data, uint16_t len, uint64_t timestamp);

	enum {
		PP_PROC_OPT_NONE             = 0,
		PP_PROC_OPT_CREATE_HASH      = 1<<0,
		PP_PROC_OPT_DUMP_EACH_PACKET = 1<<1,
		PP_PROC_OPT_DUMP_FLOWS       = 1<<2,
		PP_PROC_OPT_DUMP_TABLE_STATS = 1<<3,
		PP_PROC_OPT_DUMP_PP_STATS    = 1<<4,
		PP_PROC_OPT_USE_REST         = 1<<5,
		PP_PROC_OPT_EOL
	} processing_options;

	struct bpf_insn *bp_filter;

	/* holds the flow hash table */
	struct pp_flow_table *flow_table;

	pthread_mutex_t stats_lock;
	uint32_t unique_flows;
	uint64_t packets_seen;
	uint64_t packets_taken;
	uint64_t bytes_seen;
	uint64_t bytes_taken;

	char *rest_backend_url;

	/* packet analysers available */
	struct pp_analyzer *analyzers;
	int analyzer_num;

	enum PP_ANALYZER_MODES analyzer_mode;
	int32_t analyzer_mode_val;

	pthread_t pt_stats;
	pthread_cond_t pc_stats;
	pthread_mutex_t pm_stats;

	pthread_t pt_report;
	pthread_cond_t pc_report;
	pthread_mutex_t pm_report;
};

#endif /* __PP_CONTEXT */
