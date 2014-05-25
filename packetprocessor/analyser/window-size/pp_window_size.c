#include <pp_window_size.h>

void pp_window_size_collect(uint32_t idx, struct pp_packet_context *pkt_ctx, struct pp_flow *flow_ctx) {

	struct __pp_window_size_data *data = pp_analyzer_storage_get_next_location(idx, pkt_ctx, flow_ctx);

	if (likely(data)) {
		data->size = pkt_ctx->l4_meta.tcp.window_size;
	}
}

/**
 * @brief private analyzer callback called with analyzers data related to the given flow
 * @param data ptr to the collected data
 * @param ts timestamp of the data set
 * @param direction the associated packet was captured
 */
static void __pp_window_size_analyze(void *data, uint64_t ts, int direction) {

	struct __pp_window_size_data *ws_data = data;
	static uint16_t last_ws_up = 0;
	static uint16_t last_ws_down = 0;

	pp_window_size_report_data.data = realloc(pp_window_size_report_data.data,
										 (pp_window_size_report_data.size + 1) * sizeof(struct __pp_window_size_report_data));
	if (!pp_window_size_report_data.data) {
		pp_window_size_report_data.size = 0;
	}
	pp_window_size_report_data.data[pp_window_size_report_data.size].timestamp = ts;
	if (direction == PP_PKT_DIR_UPSTREAM) {
		pp_window_size_report_data.data[pp_window_size_report_data.size].window_size_upstream = ws_data->size;
		last_ws_up  = ws_data->size;
		pp_window_size_report_data.data[pp_window_size_report_data.size].window_size_downstream = last_ws_down;
	} else {
		pp_window_size_report_data.data[pp_window_size_report_data.size].window_size_upstream = last_ws_down;
		pp_window_size_report_data.data[pp_window_size_report_data.size].window_size_downstream = ws_data->size;
		last_ws_down  = ws_data->size;
	}
	pp_window_size_report_data.size++;
}

/* analyse function */
void pp_window_size_analyze(uint32_t idx, struct pp_flow *flow_ctx) {

	free(pp_window_size_report_data.data);
	pp_window_size_report_data.data = NULL;
	pp_window_size_report_data.size = 0;

	pp_analyzer_callback_for_each_entry(idx, flow_ctx, &__pp_window_size_analyze);
}

/* report function */
char* pp_window_size_report(uint32_t idx, struct pp_flow *flow_ctx) {

	/* TODO: transform to rest output if rest backend is enabled */

	if(pp_window_size_report_data.size > WINDOWS_SIZE_ANALYZER_MIN_SAMPLE_COUNT) {
		int i;
		char buf[16000] = {'\0'};
		int wpos = 0;

		wpos += sprintf(buf, "{");
		for (i = 0; i < pp_window_size_report_data.size; i++) {
			wpos += sprintf(&buf[wpos], "{%" PRIu64 ",%d,%d},", pp_window_size_report_data.data[i].timestamp,
																pp_window_size_report_data.data[i].window_size_upstream,
																pp_window_size_report_data.data[i].window_size_downstream);
		}
		wpos--;
		buf[wpos] = '}';
		buf[wpos + 1] = '\0';
		return strdup(buf);
	} else {
		/* no data available */
		return NULL;
	}
}

/* self description function */
char* pp_window_size_describe(struct pp_flow *flow_ctx) {

	/* TODO */
	return strdup("its me - window size analyzer");
}

/* init private data */
void pp_window_size_init(uint32_t idx, struct pp_flow *flow_ctx, enum PP_ANALYZER_MODES mode, uint32_t mode_val) {

	PP_ANALYZER_STORE_INIT(pp_window_size, idx, flow_ctx, mode, mode_val);

	pp_window_size_report_data.data = NULL;
	pp_window_size_report_data.size = 0;
}

/* free all data */
void pp_window_size_destroy(uint32_t idx, struct pp_flow *flow_ctx) {

	free(pp_window_size_report_data.data);
	pp_window_size_report_data.data = NULL;
	pp_window_size_report_data.size = 0;

	/* free analyzer data */
	pp_analyzer_storage_destroy(idx, flow_ctx);
}
