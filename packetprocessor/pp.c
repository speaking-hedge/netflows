#include "pp.h"

volatile int run;

static void set_action(struct pp_config *pp_ctx, enum pp_action action, char *packet_source);

int main(int argc, char **argv) {

	struct pp_config pp_ctx;
	int rc = 0;

	signal(SIGINT, &catch);
	signal(SIGQUIT, &catch);
	signal(SIGTERM, &catch);

	signal(SIGUSR1, &dump_state);

	parse_cmd_line(argc, argv, &pp_ctx);

	/* sanity checks */
	if (pp_ctx.pp_action == PP_ACTION_UNDEFINED) {
		fprintf(stderr, "no action specified. abort.\n");
		return 1;
	}

	if (pp_ctx.output_format == PP_OUTPUT_DATABASE &&
		(pp_ctx.db_config.host[0] == 0 ||
		pp_ctx.db_config.user == 0 ||
		pp_ctx.db_config.schema == 0 ||
		pp_ctx.db_config.port == -1)) {
		fprintf(stderr, "missing database attributes. at least host, user, schema and port are needed. abort.\n");
		return 1;
	}

	switch(pp_ctx.pp_action) {
		case PP_ACTION_CHECK:
			rc = check_file(&pp_ctx);
			break;
		case PP_ACTION_ANALYSE_FILE:
			/* TODO */
			break;
		case PP_ACTION_ANALYSE_LIVE:
			run = 1;
			while(run) {
				/* TODO */
			};
			break;
	}

    if (pp_ctx.packet_source)
		free(pp_ctx.packet_source);

	return rc;
}

/**
 * @brief parse command line options and set config in pp_ctx
 * @param argc as supplied to main
 * @param argv as supplied to main
 * @param ctx that holds the pp configuration
 */
void parse_cmd_line(int argc, char **argv, struct pp_config *pp_ctx) {

	struct option options[] = {
		{"help", 0, NULL, 'h'},
		{"version", 0, NULL, 'v'},
		{"analyse", 1, NULL, 'a'},
		{"live-analyse", 1, NULL, 'l'},
		{"check", 1, NULL, 'c'},
		{"yaml", 0, NULL, 'y'},
		{"database", 1, NULL, 'd'},
		{"db-host", 1, NULL, 'H'},
		{"db-user", 1, NULL, 'u'},
		{"db-password", 1, NULL, 'P'},
		{"db-port", 1, NULL, 'p'},
		{"db-schema", 1, NULL, 's'},
		{NULL, 0, NULL, 0}
	};
	int opt = 0, i = 0;
	char *endptr;

	pp_ctx->pp_action = PP_ACTION_UNDEFINED;
	pp_ctx->packet_source = NULL;
	pp_ctx->output_format = PP_OUTPUT_UNDEFINED;
	memset(&pp_ctx->db_config, 0, sizeof(pp_ctx->db_config));
	pp_ctx->db_config.port = -1;
	pp_ctx->db_config.type = PP_DB_UNDEFINED;

    while(1) {
		opt = getopt_long(argc, argv, "hva:l:c:yd:H:u:P:p:s:", options, NULL);
		if (opt == -1)
			break;
			
		switch(opt) {
			case '?':
				exit(1);
			case 'h':
				usage();
				exit(0);
			case 'v':
				version();
				exit(0);
			break;
			case 'a':
				set_action(pp_ctx, PP_ACTION_ANALYSE_FILE, optarg);
				break;
			case 'l':
				set_action(pp_ctx, PP_ACTION_ANALYSE_LIVE, optarg);
				break;
			case 'c':
				set_action(pp_ctx, PP_ACTION_CHECK, optarg);
				break;
			case 'y':
				if (pp_ctx->output_format != PP_OUTPUT_UNDEFINED && pp_ctx->output_format != PP_OUTPUT_YAML) {
					fprintf(stderr, "more then one output format selected but only one supported. abort.\n");
					exit(1);
				}
				pp_ctx->output_format = PP_OUTPUT_YAML;
				break;
			case 'd':
				if (pp_ctx->output_format != PP_OUTPUT_UNDEFINED && pp_ctx->output_format != PP_OUTPUT_DATABASE) {
					fprintf(stderr, "more then one output format selected but only one at a time supported. abort.\n");
					exit(1);
				}
				pp_ctx->output_format = PP_OUTPUT_DATABASE;
				pp_ctx->db_config.type = PP_DB_UNDEFINED;
				for (i = 0; i < PP_DB_EOL; i++) {
					if (0 == strcasecmp(optarg, pp_db_type_names[i])) {
						pp_ctx->db_config.type = i;
						break;
					}
				}
				if (pp_ctx->db_config.type == PP_DB_UNDEFINED) {
					fprintf(stderr, "unknown database-type given. abort.\n");
					exit(1);
				}
				break;
			case 'H': /*host*/
				strncpy(pp_ctx->db_config.host, optarg, PP_DB_CONNECTION_STRING_SIZE);
				break;
			case 'u': /*user*/
				strncpy(pp_ctx->db_config.user, optarg, PP_DB_CONNECTION_STRING_SIZE);
				break;
			case 'P': /*password*/
				strncpy(pp_ctx->db_config.password, optarg, PP_DB_CONNECTION_STRING_SIZE);
				break;
			case 's':/*schema*/
				strncpy(pp_ctx->db_config.schema, optarg, PP_DB_CONNECTION_STRING_SIZE);
				break;
			case 'p': /*port*/
				errno = 0;
				pp_ctx->db_config.port = strtol(optarg, &endptr, 10);
				if (endptr == optarg || errno == ERANGE || pp_ctx->db_config.port < 0 || pp_ctx->db_config.port > 65535) {

					fprintf(stderr, "invalid database port given. must be in [0, 65535]. abort.\n");
					exit(1);
				}
				break;
			default:
				abort();
		}
	}
}

/**
 * @brief check if given name points to a file we can open as a pcap(ng)
 * @param pp_ctx holds the config of pp
 * @retval (0) if file is valid
 * @retval (1) if file is invalid
 */
int check_file(struct pp_config *pp_ctx) {

	char errbuf[PCAP_ERRBUF_SIZE] = {'\0'};
	pcap_t *handle = pcap_open_offline(pp_ctx->packet_source, errbuf);
	if (!handle) { 
		return 1; 
	}
	pcap_close(handle);

	return 0;
}

/**
 * @brief handle signals requesting a dump of the current state
 * @param signal to handle
 */
void dump_state(int signal) {
	printf("dump state\n");
}

/**
 * @brief handle signals requesting program to exit
 * @param signal to handle
 */
void catch(int signal) {
	printf("shut down\n");
	run = 0;
}

/**
 * @brief set action  and packet source checking there was no other action selected before
 * @param pp_ctx holds the config of pp
 * @param action that is requested
 * @param packet_source points to a file or a network interface name
 */
static void set_action(struct pp_config *pp_ctx, enum pp_action action, char *packet_source) {
	if (pp_ctx->pp_action != PP_ACTION_UNDEFINED && pp_ctx->pp_action != action) {
		fprintf(stderr, "more then one action requested but only one at a time supported. abort.\n");
		exit(1);
	}
	pp_ctx->pp_action = action;
	if(pp_ctx->packet_source)
		free(pp_ctx->packet_source);
	if (!(pp_ctx->packet_source = strdup(optarg))) {
		fprintf(stderr, "failed to alloc memory for filename. abort.\n");
		exit(1);
	}
}

/**
 * @brief: show program version
 */
void version(void) {
#ifdef PPSHA
	printf("version %s (build on %s)\n", PPVERSION, PPSHA);
#else
	printf("version %s\n", PPVERSION);
#endif
}

/**
 * @brief: output programs help text
 */
void usage(void) {
	int i;
	printf("Usage: pp [OPTION] FILE\n");
	printf("processes network packets gathered from sniffed traffic to generate\n");
	printf("flow related statistics\n\n");
	printf("-c --check <file>       do not process the file, just check if \n");
	printf("                        given file is a valid pcap(ng) file\n");
	printf("-a --analyse <file>     analyse given pcap(ng) file\n");
	printf("-l --live-analyse <if>  capture and analyse traffic from given interface\n");
	printf("\n");
	printf("-v --version            show program version\n");
	printf("-h --help               show help\n");
	printf("\n");
	printf("-y --yaml               set output format yaml (default)\n");
	printf("-d --database <type>    output data to database of given type\n");
	printf("                        currently supported databases:\n");
	for (i = 0; i < PP_DB_EOL; i++) {
		printf("                        %s\n", pp_db_type_names[i]);
	}
	printf("\n");
	printf("-H --db-host <host>     address of database server (mandatory)\n");
	printf("-u --db-user <user>   	database user (mandatory)\n");
	printf("-P --db-password <pwd>  database user password (optional)\n");
	printf("-p --db-port <port>     database service port (0..65535, mandatory)\n");
	printf("-s --db-schema <name>   database schema to use (mandatory)\n");
}
