#include <pp_common.h>
#include <pp_flow.h>
#include <pp_context.h>

struct pp_window_size_data {

	struct __pp_window_size_data {
		uint16_t size;
		uint64_t time;
	} *data;
	uint32_t available_slots;
	uint32_t used_slots;
};

void pp_window_size_collect(uint32_t idx, struct pp_packet_context *pkt_ctx, struct pp_flow *flow_ctx);
void pp_window_size_analyse(uint32_t idx, struct pp_flow *flow_ctx);
char* pp_window_size_report(uint32_t idx, struct pp_flow *flow_ctx);
char* pp_window_size_describe(struct pp_flow *flow_ctx);
void pp_window_size_init(uint32_t idx, struct pp_flow *flow_ctx);
void pp_window_size_destroy(uint32_t idx, struct pp_flow *flow_ctx);
