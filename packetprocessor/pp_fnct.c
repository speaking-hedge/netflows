#include <pp.h>

/**
 * @brief init the given ctx
 * @param pp_ctx to initialize
 */
void pp_init_ctx(struct pp_config *pp_ctx) {

	pp_ctx->action = PP_ACTION_UNDEFINED;

	pp_ctx->packet_source = NULL;
	pp_ctx->output_file = NULL;
	pp_ctx->pcap_handle = NULL;

	pp_ctx->output_format = PP_OUTPUT_UNDEFINED;

	memset(&pp_ctx->db_config, 0, sizeof(pp_ctx->db_config));
	pp_ctx->db_config.port = -1;
	pp_ctx->db_config.type = PP_DB_UNDEFINED;
}

/**
 * @brief cleanup the pp context
 * @param pp_ctx to clean up
 */
void pp_cleanup_ctx(struct pp_config *pp_ctx) {

	if (pp_ctx->packet_source) {
		free(pp_ctx->packet_source);
		pp_ctx->packet_source = NULL;
	}

	if (pp_ctx->output_file) {
		free(pp_ctx->output_file);
		pp_ctx->output_file = NULL;
	}

	if (pp_ctx->pcap_handle) {
		pp_pcap_close(pp_ctx);
	}
}

/**
 * @brief check if given name points to a file we can open as a pcap(ng)
 * @param pp_ctx holds the config of pp
 * @retval (0) if file is valid
 * @retval (1) if file is invalid
 */
int pp_check_file(struct pp_config *pp_ctx) {

	int rc = pp_pcap_open(pp_ctx);
	pp_pcap_close(pp_ctx);

	return rc;
}

/**
 * @brief open pcap file referenced in pp_ctx
 * @param pp_ctx holds the config of pp
 * @retval (0) if file was opened successfully
 * @retval (1) if open file failed
 */
int pp_pcap_open(struct pp_config *pp_ctx) {

	char errbuf[PCAP_ERRBUF_SIZE] = {'\0'};
	pp_pcap_close(pp_ctx);

	pp_ctx->pcap_handle = pcap_open_offline(pp_ctx->packet_source, errbuf);
	if (!pp_ctx->pcap_handle) {
		return 1; 
	}

	return 0;
}

/**
 * @brief close pcap file handle
 * @param pp_ctx holds the config of pp
 * @retval (0) if there was an open file that could be closed
 * @retval (1) no open file or error
 */
int pp_pcap_close(struct pp_config *pp_ctx) {

	if (pp_ctx->pcap_handle) {
		pcap_close(pp_ctx->pcap_handle);
		pp_ctx->pcap_handle = NULL;
		return 0;
	}
	return 1;
}
