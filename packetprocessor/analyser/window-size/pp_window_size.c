#include <pp_window_size.h>

#define PP_WINDOW_SIZE_SLOT_STEP	100

void pp_window_size_collect(uint32_t idx, struct pp_packet_context *pkt_ctx, struct pp_flow *flow_ctx) {

	struct pp_window_size_data *pp_wnd_sz_data = (struct pp_window_size_data*)flow_ctx->analyser_data[idx];

	/* TODO: add Round-Robin-Mode */

	if (pkt_ctx->protocols[PP_OSI_LAYER_4] == IPPROTO_TCP) {
		if (unlikely(pp_wnd_sz_data->available_slots == 0)) {
			pp_wnd_sz_data->available_slots += PP_WINDOW_SIZE_SLOT_STEP;
			pp_wnd_sz_data->data = realloc(pp_wnd_sz_data->data, pp_wnd_sz_data->available_slots * sizeof(struct __pp_window_size_data ));
		}
		pp_wnd_sz_data->data[pp_wnd_sz_data->used_slots].size = pkt_ctx->l4_meta.tcp.window_size;
		pp_wnd_sz_data->data[pp_wnd_sz_data->used_slots].time = flow_ctx->last_seen;
		pp_wnd_sz_data->data[pp_wnd_sz_data->used_slots].direction = pkt_ctx->direction;
	}
}

/* analyse function */
void pp_window_size_analyse(uint32_t idx, struct pp_flow *flow_ctx) {
	/* TODO */
}

/* report function */
char* pp_window_size_report(uint32_t idx, struct pp_flow *flow_ctx) {
	/* TODO */
}

/* self description function */
char* pp_window_size_describe(struct pp_flow *flow_ctx) {
	/* TODO */
}

/* init private data */
void pp_window_size_init(uint32_t idx, struct pp_flow *flow_ctx, enum PP_ANALYSER_MODES mode, uint32_t mode_val) {

	struct pp_window_size_data *pp_wnd_sz_data = NULL;
	flow_ctx->analyser_data[idx] = malloc(sizeof(struct pp_window_size_data));

	pp_wnd_sz_data = (struct pp_window_size_data*)flow_ctx->analyser_data[idx];

	pp_wnd_sz_data->mode = mode;
	pp_wnd_sz_data->mode = mode_val;
	if (mode_val == PP_ANALYSER_MODE_PACKETCOUNT) {
		pp_wnd_sz_data->data = calloc(mode_val, sizeof(struct __pp_window_size_data ));
		pp_wnd_sz_data->available_slots = mode_val;
	} else {
		pp_wnd_sz_data->data = calloc(PP_WINDOW_SIZE_SLOT_STEP, sizeof(struct __pp_window_size_data ));
		pp_wnd_sz_data->available_slots = PP_WINDOW_SIZE_SLOT_STEP;
	}

	pp_wnd_sz_data->used_slots = 0;

}

/* free all data */
void pp_window_size_destroy(uint32_t idx, struct pp_flow *flow_ctx) {
	/* TODO */
}
