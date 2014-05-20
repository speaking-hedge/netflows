#ifndef __PP_CONTEXT
#define __PP_CONTEXT

#include <pp_analyser.h>
#include <pp_flow.h>


struct pp_config {

	enum pp_action {
		PP_ACTION_UNDEFINED,
		PP_ACTION_ANALYSE_FILE,
		PP_ACTION_ANALYSE_LIVE,
		PP_ACTION_CHECK
	} action;

	char *packet_source;
	char *output_file;

	char *job_id;

	pcap_t *pcap_handle;
	int packet_socket;

	void (*packet_handler_cb)(struct pp_config *pp_ctx, uint8_t *data, uint16_t len, uint64_t timestamp);

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

	uint32_t unique_flows;
	uint64_t packets_seen;
	uint64_t packets_taken;
	uint64_t bytes_seen;
	uint64_t bytes_taken;

	char *rest_backend_url;

	/* packet analysers available */
	struct pp_analyser *pp_analysers;
	int pp_analyser_num;

	enum PP_ANALYSER_MODES analyser_mode;
	uint32_t analyser_mode_val;
};

#endif /* __PP_CONTEXT */
