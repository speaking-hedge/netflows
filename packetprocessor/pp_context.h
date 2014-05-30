#ifndef __PP_CONTEXT
#define __PP_CONTEXT

#include <pthread.h>
#include <pp_analyzer.h>
#include <pp_flow.h>

struct pp_context {

	enum pp_action {
		PP_ACTION_UNDEFINED = 0,
		PP_ACTION_ANALYZE_FILE,
		PP_ACTION_ANALYZE_LIVE_PF_SOCKET,
		PP_ACTION_ANALYZE_LIVE_NETFILTER,
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
		PP_PROC_OPT_SHOW_FLOWTOP     = 1<<6,
		PP_PROC_OPT_USE_NDPI         = 1<<7,
		PP_PROC_OPT_LIST_NDPI_PROTOS = 1<<8,
		PP_PROC_OPT_DUMP_NDPI_STATS  = 1<<9,
		PP_PROC_OPT_CAN_DROP_PACKETS = 1<<10,
		PP_PROC_OPT_EOL
	} processing_options;

	struct bpf_insn *bp_filter;

	/* this is some kind of global lock so use it with care */
	pthread_mutex_t flow_table_lock;
	/* holds the flow hash table */
	struct pp_flow_table *flow_table;

	/* this is some kind of global lock so use it with care */
	pthread_mutex_t flow_list_lock;
	/* holds references to the flows in a list */
	struct pp_flow_list flow_list;
	uint32_t flow_list_size;

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

	pthread_t pt_flowtop;
	pthread_t pt_flowtop_keyhandler;
	uint32_t flowtop_interval;
	enum pp_flowtop_sort_criteria flowtop_sort_by;
	enum pp_flowtop_sort_order flowtop_sort_order;

	struct ndpi_detection_module_struct *ndpi_ctx;
	struct __pp_ndpi_protocol_stats {
		char *proto_name;
		uint64_t packets;
		uint64_t bytes;
	} *ndpi_protocol_stats;
};

#endif /* __PP_CONTEXT */
