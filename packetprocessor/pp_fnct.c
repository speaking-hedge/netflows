#include <pp.h>

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
