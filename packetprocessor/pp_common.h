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

enum pp_db_types {
	PP_DB_BASE = 0,
	PP_DB_MYSQL = 0,
	PP_DB_EOL,
	PP_DB_UNDEFINED
};

static char *pp_db_type_names[PP_DB_EOL] = {
	[PP_DB_MYSQL] = "mysql"
};

#define PP_DB_CONNECTION_STRING_SIZE	256
struct pp_db_connection {

	enum pp_db_types type;

	char host[PP_DB_CONNECTION_STRING_SIZE];
	int port;
	char user[PP_DB_CONNECTION_STRING_SIZE];
	char password[PP_DB_CONNECTION_STRING_SIZE];
	char schema[PP_DB_CONNECTION_STRING_SIZE];
};

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
		PP_OUTPUT_BASE = 0,
		PP_OUTPUT_YAML = 0,
		PP_OUTPUT_DATABASE,
		PP_OUTPUT_EOD,
		PP_OUTPUT_UNDEFINED
	} output_format;
	
	enum {
		PP_PROC_OPT_NONE = 0,
		PP_PROC_OPT_CREATE_HASH = 1<<0,
		PP_PROC_OPT_EOL
	} processing_options;

	struct pp_db_connection db_config;
};

#endif /* __PP_COMMON_H */
