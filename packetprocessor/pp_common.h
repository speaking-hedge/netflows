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
};

#endif /* __PP_COMMON_H */
