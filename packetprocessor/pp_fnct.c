#include <pp_fnct.h>

/**
 * @brief init the given ctx
 * @param pp_ctx to initialize
 */
void pp_init_ctx(struct pp_config *pp_ctx, void (*packet_handler)(struct pp_config *pp_ctx, uint8_t *data, uint16_t len, uint64_t timestamp)) {

	pp_ctx->action = PP_ACTION_UNDEFINED;

	pp_ctx->packet_source = NULL;
	pp_ctx->output_file = NULL;
	pp_ctx->pcap_handle = NULL;
	pp_ctx->packet_socket = 0;
	pp_ctx->packet_handler_cb = packet_handler;

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

	pp_live_shutdown(pp_ctx);
}

/**
 * @brief dump current state using selected output target and format
 * @param pp_ctx holds the config of pp
 * @note ...for sure this action must use some locking on the central data...
 */
void pp_dump_state(struct pp_config *pp_ctx) {
	/* TODO */
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

static int __pp_live_check_perm(void);

/**
 * @brief init traffic sniffing via netfilter hook
 * @retval 0 on success
 */
int pp_live_init(struct pp_config *pp_ctx) {

	struct sockaddr_ll ll_addr;

	if (pp_ctx->packet_socket) {
		return EBUSY;
	}

	if (!pp_ctx->packet_handler_cb || !pp_ctx->packet_source) {
		return EINVAL;
	}

	if(__pp_live_check_perm()) {
		return EPERM;
	}

	errno = 0;
	ll_addr.sll_ifindex = if_nametoindex(pp_ctx->packet_source);
	if (errno != 0) {
		return ENODEV;
	}

	if( 0 > (pp_ctx->packet_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))) {
		return EBADF;
	}

	ll_addr.sll_family = AF_PACKET;
	ll_addr.sll_protocol = htons(ETH_P_ALL);

	if (bind(pp_ctx->packet_socket, (struct sockaddr *)&ll_addr, sizeof(struct sockaddr_ll))) {
		close(pp_ctx->packet_socket);
		pp_ctx->packet_socket = 0;
		return EBADF;
	}

	return 0;
}

/**
 * @brief run live capture on given device invoking packet handler of given pp_ctx
 * @param pp_ctx holds the config of pp
 * @param run flag, set to 0 to stop capture
 * @param dump flag, set to 1 to trigger a dump of the current state
 * @retval 0 if capture runs/finish without errors
 * @retval 1 on error during capture
 */
int pp_live_capture(struct pp_config *pp_ctx, volatile int *run, volatile int *dump) {

	uint8_t buf[9000];
	int inb;
	struct pollfd fd = {0};
	struct sockaddr_ll src_addr;
	socklen_t addr_len = sizeof src_addr;
	struct timespec ts;

	while(*run) {
		fd.fd = pp_ctx->packet_socket;
		fd.events = POLLIN;
		switch(poll(&fd, 1, 100)) {
			case -1:
				return 1;
			case 0:
				break;
			default:
				/* TODO: get an idea how inaccurate the time measurement is */
				clock_gettime(CLOCK_MONOTONIC, &ts);
				inb = recvfrom(pp_ctx->packet_socket, buf, 9000, 0, (struct sockaddr*)&src_addr, &addr_len);
				if (inb) {
					pp_ctx->packet_handler_cb(pp_ctx, buf, inb, ts.tv_sec * 1000000 + ts.tv_nsec/1000);
					/* NOTE: packet direction -> src_addr.sll_pkttype, see man packet */
				}
		} /* __poll */
		if (*dump) {
			pp_dump_state(pp_ctx);
			*dump = 0;
		}
	} /* __while_run */

	return 0;
}

/**
 * @brief shutdown live capture socket
 * @param pp_ctx holds the config of pp
 * @retval 0 if there was a socket that could be closed
 * @retval 1 on error / no open socket found
 */
int pp_live_shutdown(struct pp_config *pp_ctx) {

	if (pp_ctx->packet_socket) {
		close(pp_ctx->packet_socket);
		pp_ctx->packet_socket = 0;
		return 0;
	}
	return 1;
}

/**
 * @brief check for proper permissions to use AF_PACKET
 * @retval 0 if sufficient permissions detected
 * @retval 1 if insufficient permissions detected
 */
static int __pp_live_check_perm(void) {

	cap_t capp;
	cap_flag_value_t v;

	if (!getuid()) {
		return 0;
	}

	if (!(capp = cap_get_proc())) {
		perror("cap_get_proc() failed");
		return -1;
	}
	if(cap_get_flag(capp, CAP_NET_RAW, CAP_EFFECTIVE, &v)) {
		perror("cap_get_flag() failed");
		return -1;
	}
	if (v == CAP_SET) {
		cap_free(capp);
		return 0;
	}
	cap_free(capp);
	return 1;
}
