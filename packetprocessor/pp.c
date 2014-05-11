#include "pp.h"

volatile int run;

static void __pp_set_action(struct pp_config *pp_ctx, enum pp_action action, char *packet_source);

int main(int argc, char **argv) {

	struct pp_config pp_ctx;
	int rc = 0;

	signal(SIGINT, &pp_catch_term);
	signal(SIGQUIT, &pp_catch_term);
	signal(SIGTERM, &pp_catch_term);

	signal(SIGUSR1, &pp_catch_dump);

	pp_parse_cmd_line(argc, argv, &pp_ctx);

	/* sanity checks */
	if (pp_ctx.action == PP_ACTION_UNDEFINED) {
		fprintf(stderr, "no action specified. abort.\n");
		pp_cleanup_ctx(&pp_ctx);
		return 1;
	}

	if (pp_ctx.output_format == PP_OUTPUT_DATABASE &&
		(pp_ctx.db_config.host[0] == 0 ||
		pp_ctx.db_config.user == 0 ||
		pp_ctx.db_config.schema == 0 ||
		pp_ctx.db_config.port == -1)) {
		fprintf(stderr, "missing database attributes. at least host, user, schema and port are needed. abort.\n");
		pp_cleanup_ctx(&pp_ctx);
		return 1;
	}

	switch(pp_ctx.action) {
		case PP_ACTION_CHECK:
			rc = pp_check_file(&pp_ctx);
			break;
		case PP_ACTION_ANALYSE_FILE:
			if(pp_pcap_open(&pp_ctx)) {
				rc = 1;
			} else {
				/* TODO */
			}
			break;
		case PP_ACTION_ANALYSE_LIVE:
			run = 1;
			while(run) {
				/* TODO */
			};
			break;
		default:
			fprintf(stderr, "unknown action specified. abort.\n");
			rc = 1;
	}

	pp_cleanup_ctx(&pp_ctx);

	return rc;
}

/**
 * @brief parse command line options and set config in pp_ctx
 * @param argc as supplied to main
 * @param argv as supplied to main
 * @param ctx that holds the pp configuration
 */
void pp_parse_cmd_line(int argc, char **argv, struct pp_config *pp_ctx) {

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
		{"output", 1, NULL, 'o'},
		{NULL, 0, NULL, 0}
	};
	int opt = 0, i = 0;
	char *endptr = NULL;

	pp_init_ctx(pp_ctx);

    while(1) {
		opt = getopt_long(argc, argv, "hva:l:c:yd:H:u:P:p:s:o:", options, NULL);
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
				__pp_set_action(pp_ctx, PP_ACTION_ANALYSE_FILE, optarg);
				break;
			case 'l':
				__pp_set_action(pp_ctx, PP_ACTION_ANALYSE_LIVE, optarg);
				break;
			case 'c':
				__pp_set_action(pp_ctx, PP_ACTION_CHECK, optarg);
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
			case 'o': /* output file */
				free(pp_ctx->output_file);
				if(!(pp_ctx->output_file = strdup(optarg))) {
					fprintf(stderr, "failed to alloc memory for output filename. abort.\n");
					exit(1);
				}
				break;
			default:
				abort();
		}
	}
}

/**
 * @brief handle signals requesting a dump of the current state
 * @param signal to handle
 */
void pp_catch_dump(int signal) {
	printf("dump state\n");
}

/**
 * @brief handle signals requesting program to exit
 * @param signal to handle
 */
void pp_catch_term(int signal) {
	printf("shut down\n");
	run = 0;
}

/**
 * @brief set action  and packet source checking there was no other action selected before
 * @param pp_ctx holds the config of pp
 * @param action that is requested
 * @param packet_source points to a file or a network interface name
 */
static void __pp_set_action(struct pp_config *pp_ctx, enum pp_action action, char *packet_source) {
	if (pp_ctx->action != PP_ACTION_UNDEFINED && pp_ctx->action != action) {
		fprintf(stderr, "more then one action requested but only one at a time supported. abort.\n");
		exit(1);
	}
	pp_ctx->action = action;
	free(pp_ctx->packet_source);
	if (!(pp_ctx->packet_source = strdup(optarg))) {
		fprintf(stderr, "failed to alloc memory while setting action. abort.\n");
		exit(1);
	}
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
	printf("-c --check <file>       do not process the file, just check if \n");
	printf("                        given file is a valid pcap(ng) file\n");
	printf("-a --analyse <file>     analyse given pcap(ng) file\n");
	printf("-l --live-analyse <if>  capture and analyse traffic from given interface\n");
	printf("\n");
	printf("-v --version            show program version\n");
	printf("-h --help               show help\n");
	printf("\n");
	printf("-y --yaml               set output format yaml (default)\n");
	printf("-o --output <file>      output to given file (default: stdout)\n");
	printf("                        for dumps requested while the analyser\n");
	printf("                        is still running, an increasing nummber is\n");
	printf("                        appended to the filename\n");
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
