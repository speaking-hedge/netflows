#include <pp_ndpi.h>

static void * __pp_malloc(size_t size);
static void __pp_free(void *ptr);

static uint32_t size_flow_struct = 0;
static uint32_t size_id_struct = 0;

/**
 * @brief malloc wrapper
 * @todo add memory pool
 * @param size in bytes of requested memory
 * @retval ptr to the allocated memory on success
 * @retval NULL on error
 */
static void * __pp_malloc(size_t size) {
	return malloc(size);
}

/**
 * @brief free wrapper
 * @todo use memory pool
 * @param ptr to the memory to be freed
 * @note ptr may point to NULL
 */
static void __pp_free(void *ptr) {
	free(ptr);
}

/**
 * @brief init ndpi detection context
 * @param pp_ctx packet processor context to attach the dpi to
 * @retval 0 on success
 * @retval 1 on error
 */
int pp_ndpi_init(struct pp_context *pp_ctx) {

	ndpi_protocol_bitmask_struct_t bm_all;
	int i = 0;

	pp_ctx->ndpi_ctx = ndpi_init_detection_module(PP_NDPI_TICKS_RESOLUTION,
											 &__pp_malloc,
											 &__pp_free,
											 NULL);

	NDPI_BITMASK_SET_ALL(bm_all);
	ndpi_set_protocol_detection_bitmask2(pp_ctx->ndpi_ctx, &bm_all);

	size_flow_struct = ndpi_detection_get_sizeof_ndpi_flow_struct();
	size_id_struct = ndpi_detection_get_sizeof_ndpi_id_struct();

	if ((pp_ctx->ndpi_protocol_stats = calloc(pp_ctx->ndpi_ctx->ndpi_num_supported_protocols, sizeof(struct __pp_ndpi_protocol_stats)))) {
		for (i = 0; i < pp_ctx->ndpi_ctx->ndpi_num_supported_protocols; i++) {
			pp_ctx->ndpi_protocol_stats[i].proto_name = pp_ctx->ndpi_ctx->proto_defaults[i].protoName;
		}
	} else {
		pp_ndpi_destroy(pp_ctx);
		return 1;
	}

	return 0;
}

/**
 * @brief free nDPI context
 * @param pp_ctx the context to free the nDPI context for
 */
void pp_ndpi_destroy(struct pp_context *pp_ctx) {

	assert(pp_ctx->ndpi_ctx);

	ndpi_exit_detection_module(pp_ctx->ndpi_ctx,
							   &__pp_free);

	free(pp_ctx->ndpi_protocol_stats);

	pp_ctx->ndpi_ctx = NULL;
}

/**
 * @brief create a new ndpi flow and attach it to the pp_flow given
 * @param flow_ctx the flow to attach the ndpi_flow to
 * @param pkt_ctx holds packet informations of the current packet
 * @retval 0 on success
 * @retval 1 on error
 */
int pp_ndpi_flow_attach(struct pp_flow *flow_ctx, struct pp_packet_context *pck_ctx) {

	assert(flow_ctx);
	assert(pck_ctx);

	if(!(flow_ctx->ndpi_flow_ctx = (struct ndpi_flow_struct*)calloc(1, size_flow_struct))) {
		return 1;
	}

	if((flow_ctx->ndpi_src = calloc(1, size_id_struct)) == NULL) {
		free(flow_ctx->ndpi_flow_ctx);
		flow_ctx->ndpi_flow_ctx = NULL;
		return 1;
	}

	if((flow_ctx->ndpi_dst = calloc(1, size_id_struct)) == NULL) {
		free(flow_ctx->ndpi_flow_ctx);
		free(flow_ctx->ndpi_src);
		flow_ctx->ndpi_flow_ctx = NULL;
		flow_ctx->ndpi_src = NULL;
		return 1;
	}

	return 0;
}

/**
 * @brief return the protocol name for the protocol given by id
 * @param pp_ctx packet processor context that holds the ndpi context
 * @param protocol_id id of the protocol to get the name for
 * @retval name of the protocol if ndpi enabled
 * @retval <ndpi disabled> if ndpi is not used
 */
inline const char* pp_ndpi_get_protocol_name(struct pp_context *pp_ctx, uint32_t protocol_id) {

	assert(pp_ctx);

	if (pp_ctx->ndpi_ctx) {
		return ndpi_get_proto_name(pp_ctx->ndpi_ctx, protocol_id);
	} else {
		return "<ndpi disabled>";
	}
}

/**
 * @brief return the id of the protocol given by name
 * @param pp_ctx packet processor context that holds the ndpi context
 * @param protocol_name (caseinsensitive) of the protocol to return the id for
 * @retval id of the protocol if ndpi enabled and protocol was found
 * @retval 0 if ndpi is not used or protocol is unknown
 */
uint32_t pp_ndpi_get_protocol_id(struct pp_context *pp_ctx, const char *protocol_name) {

	int i = 0;
	struct ndpi_detection_module_struct *ndpi_ctx = NULL;

	assert(pp_ctx);

	if (!pp_ctx->ndpi_ctx || !protocol_name) {
		return 0;
	}

	ndpi_ctx = pp_ctx->ndpi_ctx;

	for (i = 0; i < ndpi_ctx->ndpi_num_supported_protocols; i++) {
		if (!strcasecmp(protocol_name, ndpi_ctx->proto_defaults[i].protoName)) {
			return i;
		}
	}

	return 0;
}

/**
 * @brief return an array containing ptrs to the names of the supported protocols
 * @note the caller must free the list but not strings stored inside
 * @param pp_ctx packet processor context that holds the ndpi context
 * @param protocol_list [OUT] where to store the list
 * @retval >=0 number of protocols in the list
 * @retval <0 on error
 */
int pp_ndpi_get_protocol_list(struct pp_context *pp_ctx, char *** protocol_list) {

	struct ndpi_detection_module_struct *ndpi_ctx = NULL;
	int i = 0;

	assert(pp_ctx);

	if (!pp_ctx->ndpi_ctx) {
		return 0;
	}

	ndpi_ctx = pp_ctx->ndpi_ctx;

	if (!(*protocol_list = malloc(ndpi_ctx->ndpi_num_supported_protocols * sizeof(char*)))) {
		return -1;
	}

	for (i = 0; i < ndpi_ctx->ndpi_num_supported_protocols; i++) {
		(*protocol_list)[i] = ndpi_ctx->proto_defaults[i].protoName;
	}

	return ndpi_ctx->ndpi_num_supported_protocols;
}

/**
 * @brief dump nDPI protocol stats
 * @param pp_ctx packet processor context that holds the ndpi context
 */
void pp_ndpi_stats_dump(struct pp_context *pp_ctx) {

	int i = 0;
	struct __pp_ndpi_protocol_stats *proto_stats = NULL;
	double p_per_b = 100.0 / pp_ctx->bytes_taken;

	if (!pp_ctx->ndpi_ctx) {
		return;
	}

	printf("%-20s %12s %12s    %10s\n", "protocol", "packets", "bytes", "traffic/%");
	for (i = 0; i < pp_ctx->ndpi_ctx->ndpi_num_supported_protocols; i++) {

		proto_stats = &pp_ctx->ndpi_protocol_stats[i];

		if (proto_stats->bytes) {
			printf("%-20s %12" PRIu64 " %12" PRIu64 "    %10.2f\n", proto_stats->proto_name,
										  proto_stats->packets,
										  proto_stats->bytes,
										  p_per_b * proto_stats->bytes);
		}
	}
}
