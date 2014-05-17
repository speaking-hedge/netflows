#ifndef __PP_COMMON_H
#define __PP_COMMON_H

#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pcap/bpf.h>
#include <ethertype.h>

struct pp_config {

	enum pp_action {
		PP_ACTION_UNDEFINED,
		PP_ACTION_ANALYSE_FILE,
		PP_ACTION_ANALYSE_LIVE,
		PP_ACTION_CHECK
	} action;

	char *packet_source;
	char *output_file;

	pcap_t *pcap_handle;
	int packet_socket;

	void (*packet_handler_cb)(struct pp_config *pp_ctx, uint8_t *data, uint16_t len, uint64_t timestamp);

	enum {
		PP_PROC_OPT_NONE = 0,
		PP_PROC_OPT_CREATE_HASH = 1<<0,
		PP_PROC_OPT_EOL
	} processing_options;

	struct bpf_insn *bp_filter;
};

enum PP_DECAP_RESULT {
	/* packet successfull decapsulated and analysed */
	PP_DECAP_OKAY = 0,
	/* l2 error during packet decapsulation */
	PP_DECAP_L2_ERROR,
	/* l3 error during packet decapsulation */
	PP_DECAP_L3_ERROR,
	/* l4 error during packet decapsulation */
	PP_DECAP_L4_ERROR,
	/* l2 - protocol not supported */
	PP_DECAP_L2_PROTO_UNKNOWN,
	/* l3 - protocol not supported */
	PP_DECAP_L3_PROTO_UNKNOWN,
	/* l4 - protocol not supported */
	PP_DECAP_L4_PROTO_UNKNOWN,
	PP_DECPA_EOL
};

#endif /* __PP_COMMON_H */
