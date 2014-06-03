#ifndef __APPLICATION_FILTER
#define __APPLICATION_FILTER

#include <pp_analyzer.h>
#include <pp_flow.h>
#include <pp_context.h>

/* unique database id */
#define PP_APPLICATION_FILTER_ANALYZER_DB_ID 4

/* appllication  specific data */
struct __pp_application_filter_data {

	uint32_t protocol_id;
	char* protocol_name;
	uint32_t dropped_upstream_packets;
	uint32_t dropped_downstream_packets;
	uint64_t dropped_upstream_bytes;
	uint64_t dropped_downstream_bytes;

	struct __pp_application_filter_data *next;
};

enum PP_ANALYZER_ACTION pp_application_filter_inspect(uint32_t idx, struct pp_packet_context *pkt_ctx, struct pp_flow *flow_ctx);
char* pp_application_filter_describe(void);
void pp_application_filter_init(uint32_t idx, struct pp_flow *flow_ctx, enum PP_ANALYZER_MODES mode, uint32_t mode_val);
void pp_application_filter_destroy(uint32_t idx, struct pp_flow *flow_ctx);
uint32_t pp_application_filter_id(void);

int pp_application_filter_protocol_add(const char* protocol_name);
int pp_applictaion_filter_protocol_init(struct pp_context *pp_ctx);

void pp_application_filter_status_dump();

#endif /* __APPLICATION_FILTER */
