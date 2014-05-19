#ifndef __PP_CONTEXT
#define __PP_CONTEXT

#include <pp_common.h>
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
		PP_PROC_OPT_NONE = 0,
		PP_PROC_OPT_CREATE_HASH = 1<<0,
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

	int rest;
	char *rest_url;
};

#endif /* __PP_CONTEXT */
