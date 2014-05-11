#ifndef __PP_H
#define __PP_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <getopt.h>
#include <errno.h>
#include <signal.h>
#include <string.h>

#define PPVERSION "0.1"

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

	enum {
		PP_OUTPUT_BASE = 0,
		PP_OUTPUT_YAML = 0,
		PP_OUTPUT_DATABASE,
		PP_OUTPUT_EOD,
		PP_OUTPUT_UNDEFINED
	} output_format;

	struct pp_db_connection db_config;
};

void pp_parse_cmd_line(int argc, char **argv, struct pp_config *pp_ctx);

void pp_init_ctx(struct pp_config *pp_ctx);
void pp_cleanup_ctx(struct pp_config *pp_ctx);
int pp_check_file(struct pp_config *pp_ctx);

int pp_pcap_open(struct pp_config *pp_ctx);
int pp_pcap_close(struct pp_config *pp_ctx);

void pp_catch_dump(int signal);
void pp_catch_term(int signal);

void pp_usage(void);
void pp_version(void);

#endif /* __PP_H */
