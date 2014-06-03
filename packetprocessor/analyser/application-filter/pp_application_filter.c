#include <pp_application_filter.h>

/* global filter data */
static struct __pp_application_filter_data *app_filter_data = NULL;

enum PP_ANALYZER_ACTION pp_application_filter_inspect(uint32_t idx, struct pp_packet_context *pkt_ctx, struct pp_flow *flow_ctx) {

	struct __pp_application_filter_data *cur_filter_data = app_filter_data;

	while(cur_filter_data) {

		/* TODO: for faster access -> use an array with size of number_of_supported_protocols... */
		if (cur_filter_data->protocol_id == flow_ctx->ndpi_protocol) {

			if (pkt_ctx->direction == PP_PKT_DIR_UPSTREAM) {
				cur_filter_data->dropped_downstream_packets++;
				cur_filter_data->dropped_downstream_bytes += pkt_ctx->length;
			} else {
				cur_filter_data->dropped_upstream_packets++;
				cur_filter_data->dropped_upstream_bytes += pkt_ctx->length;
			}
			return PP_ANALYZER_ACTION_DROP;
		}

		cur_filter_data = cur_filter_data->next;
	}

	return PP_ANALYZER_ACTION_NONE;
}

/* dump status of the filter */
void pp_application_filter_status_dump() {

	struct __pp_application_filter_data *cur = app_filter_data;

    if(cur) {

		printf("--app-filter---------------------------------------------------------\n");
		printf("                    upstream dropped              downstream dropped\n");
		printf("protocol           packets       bytes           packets       bytes\n");

		while (cur) {
			printf("%-14s  %10d  %10" PRIu64 "        %10d  %10" PRIu64 "\n", cur->protocol_name,
																	   cur->dropped_upstream_packets,
																	   cur->dropped_upstream_bytes,
																	   cur->dropped_downstream_packets,
																	   cur->dropped_downstream_bytes);
			cur = cur->next;
		}
	} else {
		printf("app filter: no packets dropped\n");
	}
}

/* self description function */
char* pp_application_filter_describe(void) {

	/* TODO */
	return strdup("sample analyzer - drop application packets");
}

/* init private data */
void pp_application_filter_init(uint32_t idx, struct pp_flow *flow_ctx, enum PP_ANALYZER_MODES mode, uint32_t mode_val) {
	/* NOP */
}

/* free all data */
void pp_application_filter_destroy(uint32_t idx, struct pp_flow *flow_ctx) {

	struct __pp_application_filter_data *cur;

	while (app_filter_data) {
		cur = app_filter_data;
		app_filter_data = app_filter_data->next;
		free(cur->protocol_name);
		free(cur);
	}
}

/* return unique analyzer db id */
uint32_t pp_application_filter_id(void) {
	return PP_APPLICATION_FILTER_ANALYZER_DB_ID;
}

/**
 * @brief add protocol to list of protocols to be dropped
 * @note this function does not validate the given protocol name against the
 * list of available protocols offered by the used DPI engine
 * @param protocol_name of the protocol to be added
 * @retval 0 on success
 * @retval EADDRINUSE if protocol name is already in the list
 * @retval ENOMEM on error
 */
int pp_application_filter_protocol_add(const char* protocol_name) {

	struct __pp_application_filter_data *proto = NULL;

	proto = app_filter_data;
	while(proto) {
		if (!strcasecmp(proto->protocol_name, protocol_name)) {
			return EADDRINUSE;
		}
		proto = proto->next;
	}

	if (!(proto = calloc(1, sizeof(struct __pp_application_filter_data)))) {
		return ENOMEM;
	}

	proto->protocol_id = 0;
	proto->protocol_name = strdup(protocol_name);
	proto->next = app_filter_data;
	app_filter_data = proto;

	return 0;
}

/**
 * @brief init protocol ids of filter entries
 * @param pp_ctx context that contains the ndpi ctx
 * @retval 0 on success
 * @retval 1 on error
 */
int pp_applictaion_filter_protocol_init(struct pp_context *pp_ctx) {

	struct __pp_application_filter_data *entry = NULL;
	uint32_t proto_id = 0;

	entry = app_filter_data;
	while(entry) {
		proto_id = pp_ndpi_get_protocol_id(pp_ctx, entry->protocol_name);

		if (proto_id) {
			entry->protocol_id = proto_id;
		} else {
			fprintf(stderr, "unknown protocol %s given.\nuse --list-ndpi-protocols to get a list of available protocols. abort.\n", entry->protocol_name);
			return 1;
		}
		entry = entry->next;
	}
	return 0;
}
