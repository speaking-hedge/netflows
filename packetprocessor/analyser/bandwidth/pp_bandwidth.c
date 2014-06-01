#include <pp_bandwidth.h>

enum PP_ANALYZER_ACTION pp_bandwidth_inspect(uint32_t idx, struct pp_packet_context *pkt_ctx, struct pp_flow *flow_ctx) {

	struct __pp_bandwidth_data *data = pp_analyzer_storage_get_next_location(idx, pkt_ctx, flow_ctx);

	if (likely(data)) {
		data->bytes = pkt_ctx->length;
	}

	return PP_ANALYZER_ACTION_NONE;
}

/**
 * @brief private analyzer callback called with analyzers data related to the given flow
 * @param data ptr to the collected data
 * @param ts timestamp of the data set
 * @param direction the associated packet was captured
 */
static void __pp_bandwidth_analyze(void *data, uint64_t ts, int direction) {

	struct __pp_bandwidth_data *bandwidth_data = data;

	if (pp_bandwidth_report_data.size == 0 ||
		(pp_bandwidth_report_data.size > 0 &&
		 (ts - pp_bandwidth_report_data.data[pp_bandwidth_report_data.size - 1].start_ts_usec) >= BANDWIDTH_ANALYZER_RESOLUTION)) {

		/* add new sample set */
		pp_bandwidth_report_data.size++;
		pp_bandwidth_report_data.data = realloc(pp_bandwidth_report_data.data,
												(pp_bandwidth_report_data.size) * sizeof(struct __pp_bandwidth_report_data));

		if (!pp_bandwidth_report_data.data) {
			pp_bandwidth_report_data.size = 0;
			return;
		}

		pp_bandwidth_report_data.data[pp_bandwidth_report_data.size - 1].start_ts_usec = ts;
		pp_bandwidth_report_data.data[pp_bandwidth_report_data.size - 1].end_ts_usec = 0;
		pp_bandwidth_report_data.data[pp_bandwidth_report_data.size - 1].is_valid = 0;

		pp_bandwidth_report_data.data[pp_bandwidth_report_data.size - 1].bytes_upstream = 0;
		pp_bandwidth_report_data.data[pp_bandwidth_report_data.size - 1].bytes_downstream = 0;
	}

	/* add data */
	pp_bandwidth_report_data.data[pp_bandwidth_report_data.size - 1].end_ts_usec = ts;
	if (direction == PP_PKT_DIR_UPSTREAM) {
		pp_bandwidth_report_data.data[pp_bandwidth_report_data.size - 1].bytes_upstream += bandwidth_data->bytes;
	} else {
		pp_bandwidth_report_data.data[pp_bandwidth_report_data.size - 1].bytes_downstream += bandwidth_data->bytes;
	}
}

/* analyse function */
void pp_bandwidth_analyze(uint32_t idx, struct pp_flow *flow_ctx) {

	int i = 0;
	uint64_t delta_t = 0;

	free(pp_bandwidth_report_data.data);
	pp_bandwidth_report_data.data = NULL;
	pp_bandwidth_report_data.size = 0;
	i = pp_analyzer_callback_for_each_entry(idx, flow_ctx, &__pp_bandwidth_analyze);

	/* calculate bandwith for all entries */
	for (i = 0; i < pp_bandwidth_report_data.size; i++) {

		delta_t = pp_bandwidth_report_data.data[i].end_ts_usec -
						pp_bandwidth_report_data.data[i].start_ts_usec;

		/* accept +10% inaccuracy */
		if (delta_t >= (BANDWIDTH_ANALYZER_RESOLUTION*0.90)) {

			pp_bandwidth_report_data.data[i].sample_time_usec =
				pp_bandwidth_report_data.data[i].start_ts_usec + (delta_t/2);

			pp_bandwidth_report_data.data[i].bandwidth_upstream =
				pp_bandwidth_report_data.data[i].bytes_upstream * 800000. / delta_t;

			pp_bandwidth_report_data.data[i].bandwidth_downstream =
				pp_bandwidth_report_data.data[i].bytes_downstream * 800000. / delta_t;

			pp_bandwidth_report_data.data[i].bandwidth_total =
				pp_bandwidth_report_data.data[i].bandwidth_upstream +
				pp_bandwidth_report_data.data[i].bandwidth_downstream;

			pp_bandwidth_report_data.data[i].is_valid = 1;

		} /* covers valid timespan */
	} /* __loop_entries */
}

/**
 * @brief create a bandwidth report
 * @note the caller must free the returned string
 * @retval ptr to string containing the report
 * @retval NULL on error
 */
char* pp_bandwidth_report(uint32_t idx, struct pp_flow *flow_ctx) {

	int i = 0, c = 0;
	char *buf = NULL;
	uint32_t buf_size = BANDWIDTH_ANALYZER_REPORT_BUFFER_STEP;
	int wpos = 0;

	/* TODO@SIMON: transform to rest output if rest backend is enabled */

	if(pp_bandwidth_report_data.size > BANDWIDTH_ANALYZER_MIN_SAMPLE_COUNT) {

		if (!(buf = malloc(buf_size * sizeof(char)))) {
			return NULL;
		}

		wpos += sprintf(buf, "{");
		for (i = 0; i < pp_bandwidth_report_data.size; i++) {

			if (pp_bandwidth_report_data.data[i].is_valid) {
				c++;
				wpos += sprintf(&buf[wpos], "{%" PRIu64 ",%.0f,%.0f,%.0f},", pp_bandwidth_report_data.data[i].sample_time_usec,
																	pp_bandwidth_report_data.data[i].bandwidth_upstream,
																	pp_bandwidth_report_data.data[i].bandwidth_downstream,
																	pp_bandwidth_report_data.data[i].bandwidth_total);
			}

			if (wpos > (buf_size - 200)) {
				buf_size += BANDWIDTH_ANALYZER_REPORT_BUFFER_STEP;
				if (!(buf = realloc(buf, buf_size * sizeof(char)))) {
					return NULL;
				}
			}
		} /* __loop collected report data */

		if ( c == 0 ) {
			free(buf);
			return NULL;
		}

		wpos--;
		buf[wpos] = '}';
		buf[wpos + 1] = '\0';

		return buf;

	} else {
		/* no data available */
		return NULL;
	}
}

/* self description function */
char* pp_bandwidth_describe(struct pp_flow *flow_ctx) {

	/* TODO */
	return strdup("calculate used bandwidth per flow in bit per second");
}

/* init private data */
void pp_bandwidth_init(uint32_t idx, struct pp_flow *flow_ctx, enum PP_ANALYZER_MODES mode, uint32_t mode_val) {

	PP_ANALYZER_STORE_INIT(pp_bandwidth, idx, flow_ctx, mode, mode_val);

	pp_bandwidth_report_data.data = NULL;
	pp_bandwidth_report_data.size = 0;
}

/* free all data */
void pp_bandwidth_destroy(uint32_t idx, struct pp_flow *flow_ctx) {

	free(pp_bandwidth_report_data.data);
	pp_bandwidth_report_data.data = NULL;
	pp_bandwidth_report_data.size = 0;

	/* free analyzer data */
	pp_analyzer_storage_destroy(idx, flow_ctx);
}
