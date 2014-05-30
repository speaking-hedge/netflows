#include <pp_fnct.h>

static int __pp_create_hash(struct pp_context *pp_ctx, char **hash);

/**
 * @brief init the given ctx
 * @param pp_ctx to initialize
 * @retval 0 on success
 * @retval 1 on error
 */
int pp_ctx_init(struct pp_context *pp_ctx, void (*packet_handler)(struct pp_context *pp_ctx, uint8_t *data, uint16_t len, uint64_t timestamp)) {

	pp_ctx->action = PP_ACTION_UNDEFINED;

	pp_ctx->packet_source = NULL;
	pp_ctx->output_file = NULL;
	pp_ctx->job_id = NULL;
	pp_ctx->pcap_handle = NULL;
	pp_ctx->packet_socket = 0;
	pp_ctx->packet_handler_cb = packet_handler;

	pp_ctx->processing_options = PP_PROC_OPT_NONE;

	pp_ctx->bp_filter = NULL;

	if (!(pp_ctx->flow_table = pp_flow_table_create(PP_FLOW_HASH_TABLE_BUCKETS,
													NULL,
													NULL))) {
		return 1;
	}

	pthread_mutex_init(&pp_ctx->stats_lock, NULL);
	pp_ctx->unique_flows = 0;
	pp_ctx->packets_seen = 0;
	pp_ctx->packets_taken = 0;
	pp_ctx->bytes_seen = 0;
	pp_ctx->bytes_taken = 0;

	pp_ctx->rest_backend_url = NULL;

	pp_ctx->analyzers = NULL;
	pp_ctx->analyzer_num = 0;

	pp_ctx->analyzer_mode = PP_ANALYZER_MODE_INFINITY;
	pp_ctx->analyzer_mode_val = 0;

	pthread_cond_init(&pp_ctx->pc_stats, NULL);
	pthread_mutex_init(&pp_ctx->pm_stats, NULL);
	pthread_cond_init(&pp_ctx->pc_report, NULL);
	pthread_mutex_init(&pp_ctx->pm_report, NULL);

	pthread_mutex_init(&pp_ctx->flow_table_lock, NULL);
	pthread_mutex_init(&pp_ctx->flow_list_lock, NULL);
	pp_ctx->flow_list.head = pp_ctx->flow_list.tail = NULL;
	pp_ctx->flow_list_size = 0;

	pp_ctx->ndpi_ctx = NULL;

	return 0;
}

/**
 * @brief cleanup the pp context
 * @param pp_ctx to clean up
 */
void pp_ctx_cleanup(struct pp_context *pp_ctx) {

	int b = 0;
	struct pp_flow *cur_flow, *next_flow;

	free(pp_ctx->packet_source);
	pp_ctx->packet_source = NULL;

	free(pp_ctx->output_file);
	pp_ctx->output_file = NULL;

	if (pp_ctx->pcap_handle) {
		pp_pcap_close(pp_ctx);
		pp_ctx->pcap_handle = NULL;
	}

	free(pp_ctx->bp_filter);
	pp_ctx->bp_filter = NULL;

	free(pp_ctx->job_id);
	pp_ctx->job_id = NULL;

	pp_live_socket_shutdown(pp_ctx);

	for (b = 0; b < pp_ctx->flow_table->size; b++) {
		if (pp_ctx->flow_table->buckets[b] != NULL) {
			cur_flow = pp_ctx->flow_table->buckets[b];
			do {
				next_flow = cur_flow->next_flow;

				pp_detach_analyzers_from_flow(pp_ctx, cur_flow);

				cur_flow = next_flow;
			} while (cur_flow);
		}
	}

	pp_flow_table_delete(pp_ctx->flow_table);
	pp_ctx->flow_table = NULL;

	free(pp_ctx->rest_backend_url);
	pp_ctx->rest_backend_url = NULL;

	pthread_cond_destroy(&pp_ctx->pc_stats);
	pthread_mutex_destroy(&pp_ctx->pm_stats);
	pthread_cond_destroy(&pp_ctx->pc_report);
	pthread_mutex_destroy(&pp_ctx->pm_report);

	if (pp_ctx->ndpi_ctx) {
		pp_ndpi_destroy(pp_ctx);
	}
}

/**
 * @brief check if given name points to a file we can open as a pcap(ng)
 * @param pp_ctx holds the config of pp
 * @retval (0) if file is valid
 * @retval (1) if file is invalid
 */
int pp_check_file(struct pp_context *pp_ctx) {

	int rc = pp_pcap_open(pp_ctx);
	char *hash = NULL;
	pp_pcap_close(pp_ctx);

	if (!rc && (pp_ctx->processing_options & PP_PROC_OPT_CREATE_HASH)) {
		if(__pp_create_hash(pp_ctx, &hash)) {
			rc = 1;
		} else {
			printf("%s\n", hash);
			free(hash);
		}
	}

	return rc;
}

/**
 * @brief open pcap file referenced in pp_ctx
 * @param pp_ctx holds the config of pp
 * @retval (0) if file was opened successfully
 * @retval (1) if open file failed
 */
int pp_pcap_open(struct pp_context *pp_ctx) {

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
int pp_pcap_close(struct pp_context *pp_ctx) {

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
int pp_live_socket_init(struct pp_context *pp_ctx) {

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
int pp_live_socket_capture(struct pp_context *pp_ctx, volatile int *run) {

	uint8_t buf[9000];
	int inb;
	struct pollfd fd = {0};
	struct sockaddr_ll src_addr;
	socklen_t addr_len = sizeof src_addr;
	struct timespec ts, ppoll_tout;
	sigset_t sigmask;

	ppoll_tout.tv_sec = 0;
	ppoll_tout.tv_nsec = 250000;
	sigfillset(&sigmask);

	while(*run) {
		fd.fd = pp_ctx->packet_socket;
		fd.events = POLLIN;
		switch(ppoll(&fd, 1, &ppoll_tout, &sigmask)) {
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
	} /* __while_run */

	return 0;
}

/**
 * @brief shutdown live capture socket
 * @param pp_ctx holds the config of pp
 * @retval 0 if there was a socket that could be closed
 * @retval 1 on error / no open socket found
 */
int pp_live_socket_shutdown(struct pp_context *pp_ctx) {

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

/**
 * @brief create sha256 hash over given file
 * if the file size <= 5120 the whole file is used to generate the hash
 * if the file size is > 5120, 10 equal distributed probes of 512 bytes
 * will be used to calculate the hash
 * @param pp_ctx holds the config of pp
 * @param [out] hash - where to store the ptr to the created hash
 * @note the caller takes the ownership of the hash string and must
 * free the memory used to store the string
 * @retval 0 if hash was created
 * @retval 1 on error
 */
static int __pp_create_hash(struct pp_context *pp_ctx, char **hash) {

	gcry_md_hd_t hd;
	FILE *fh = NULL;
	size_t fsize = 0;
	int i = 0;
	uint8_t buf[512], *hash_bin = NULL;
	char *hash_str = NULL;
	int gap = 0;

	if ( !(fh = fopen(pp_ctx->packet_source, "r"))) {
		return 1;
	}

	if (fseek(fh, 0, SEEK_END)) {
		fclose(fh);
		return 1;
	}
	fsize = ftell(fh);
	gap = (fsize - 5120) / 9;

	if (GPG_ERR_NO_ERROR != gcry_md_open(&hd, GCRY_MD_SHA256, 0)) {
		return 1;
	}

	if (fsize <= 5120) {
		/* suck in complete file */
		if (!fseek(fh, 0, SEEK_SET)) {
			while(1) {
				i = fread(buf, 1, 512, fh);
				if (i > 0) {
					gcry_md_write (hd, (void*)buf, i);
				} else {
					break;
				}
			}
		}
	} else {
		/* take some probes @ different places of the file */
		for ( i = 0; i < 10; i++) {
			if (fseek(fh, (i*512 +  i*gap), SEEK_SET)) {
				fclose(fh);
				return 1;
			}

			if (512 != fread(buf, 1, 512, fh)) {
				fclose(fh);
				return 1;
			}
			gcry_md_write (hd, (void*)buf, 512);
		}
	}

	if (!(hash_str = calloc(1, 65))) {
		gcry_md_close(hd);
		return 1;
	}

	hash_bin = gcry_md_read (hd, GCRY_MD_SHA256);
	for (i = 0; i < gcry_md_get_algo_dlen(GCRY_MD_SHA256); i++) {
		sprintf(&hash_str[i*2],"%02x", hash_bin[i]);
	}
	*hash = hash_str;

	gcry_md_close(hd);

	return 0;
}

/**
 * @brief get printable name for requested protocol@given layer
 * @param layer the protocol is located on
 * @param protocol the name is requested for
 * @param buf [out] points to a buffer to place the string onto
 * @param buf_len is the size of the buffer
 * @retval 0 on success
 * @retval 1 on failure, the string "unknown" is placed into buf
 */
int pp_get_proto_name(uint layer, uint32_t protocol, char* buf, size_t buf_len) {

	switch (layer) {
	case PP_OSI_LAYER_3:
		switch(protocol) {
		case ETH_P_IP:
			strncpy(buf, "IPv4", buf_len);
			return 0;
		case ETH_P_IPV6:
			strncpy(buf, "IPv6", buf_len);
			return 0;
		}
		break;
	case PP_OSI_LAYER_4:
		switch(protocol) {
		case IPPROTO_TCP:
			strncpy(buf, "TCP", buf_len);
			return 0;
		case IPPROTO_UDP:
			strncpy(buf, "UDP", buf_len);
			return 0;
		}
		break;
	}

	strncpy(buf, "unknown", buf_len);
	return 1;
}

/**
 * @brief attach and init analyzers to flow
 * @note this function is not thread save
 * @param pp_ctx context of the packetprozessor
 * @param flow to attach the analyzers to
 * @retval 0 on success
 * @retval 1 on error
 */
inline int pp_attach_analyzers_to_flow(struct pp_context *pp_ctx, struct pp_flow *flow_ctx) {

	struct pp_analyzer *analyzer = NULL;

	if (!(flow_ctx->analyzer_data = calloc(pp_ctx->analyzer_num, sizeof(struct pp_analyzer_store_void)))) {
		pthread_mutex_unlock(&flow_ctx->lock);
		return 1;
	}

	/* init flow local data for each analyzer */
	analyzer = pp_ctx->analyzers;
	while(analyzer) {
		analyzer->init(analyzer->idx,
						flow_ctx,
						pp_ctx->analyzer_mode,
						pp_ctx->analyzer_mode_val);
		analyzer = analyzer->next_analyzer;
	}

	return 0;
}

/**
 * @brief detach and free analyzers from flow
 * @param pp_ctx context of the packetprozessor
 * @param flow to free the analyzers for
 */
inline void pp_detach_analyzers_from_flow(struct pp_context *pp_ctx, struct pp_flow *flow_ctx) {

	int a = 0;

	pthread_mutex_lock(&flow_ctx->lock);

	/* init flow local data for each analyzer */
	for (a = 0; a < pp_ctx->analyzer_num; a++) {
		pp_ctx->analyzers[a].destroy(pp_ctx->analyzers[a].idx,
									 flow_ctx);
	}

	free(flow_ctx->analyzer_data);
	flow_ctx->analyzer_data = NULL;

	pthread_mutex_unlock(&flow_ctx->lock);

}


/**
 * @brief init traffic sniffing via netfilter hook
 * @retval 0 on success
 */
int pp_live_netfilter_init(struct pp_context *pp_ctx) {

	if (setuid(0)) {
		return EPERM;
	}

	/* setup netfilter queue hook
	*
	*  add queue hock:
	*  sudo iptables -A INPUT -i eth0 -p tcp -j NFQUEUE --queue-num 0
	* remove:
	*  sudo iptables -D INPUT -i eth0 -p tcp -j NFQUEUE --queue-num 0
	* */
	printf("%s\n", pp_ctx->packet_source);
	exit(1);

}

/**
 * @brief run live capture on given device invoking packet handler of given pp_ctx
 * @param pp_ctx holds the config of pp
 * @param run flag, set to 0 to stop capture
 * @param dump flag, set to 1 to trigger a dump of the current state
 * @retval 0 if capture runs/finish without errors
 * @retval 1 on error during capture
 */
int pp_live_netfilter_capture(struct pp_context *pp_ctx, volatile int *run) {

	return 0;
}

/**
 * @brief shutdown live capture socket
 * @param pp_ctx holds the config of pp
 * @retval 0 if there was a socket that could be closed
 * @retval 1 on error / no open socket found
 */
int pp_live_netfilter_shutdown(struct pp_context *pp_ctx) {

	return 0;
}
