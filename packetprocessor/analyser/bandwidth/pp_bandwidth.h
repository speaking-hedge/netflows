#ifndef __PP_BANDWIDTH
#define __PP_BANDWIDTH

#include <pp_analyzer.h>
#include <pp_flow.h>

/* number of statistic entries we need to generate a reliable report */
#define BANDWIDTH_ANALYZER_MIN_SAMPLE_COUNT	1

/* minimum delta t between two samples is BANDWIDTH_ANALYZER_RESOLUTION mikro seconds (100000 -> 100ms)*/
#define BANDWIDTH_ANALYZER_RESOLUTION	100000

/* step size of the string buffer used for reporting */
#define BANDWIDTH_ANALYZER_REPORT_BUFFER_STEP	4000

/* bandwidth analyser specific data */
struct __pp_bandwidth_data {
	uint32_t bytes;
};

static struct {
	struct __pp_bandwidth_report_data {
		/* start time of the sample set */
		uint64_t start_ts_usec;
		/* time of the last sample in set */
		uint64_t end_ts_usec;
		/* bytes consumed in each direction */
		uint32_t bytes_upstream;
		uint32_t bytes_downstream;
		/* bandwidth in bytes / second in each direction */
		double bandwidth_upstream;
		double bandwidth_downstream;
		double bandwidth_total;
		/* timestamp for the sample (= start_ts_usec + (end_ts_usce - start_ts_usec)/2) */
		uint64_t sample_time_usec;
		/* filter entries with delta t = 0 */
		uint8_t is_valid;

	} *data;
	uint32_t size;
} pp_bandwidth_report_data;

/* create storage struct*/
PP_ANALYZER_STORE_CREATE(pp_bandwidth, struct __pp_bandwidth_data);

enum PP_ANALYZER_ACTION pp_bandwidth_inspect(uint32_t idx, struct pp_packet_context *pkt_ctx, struct pp_flow *flow_ctx);
void pp_bandwidth_analyze(uint32_t idx, struct pp_flow *flow_ctx);
char* pp_bandwidth_report(uint32_t idx, struct pp_flow *flow_ctx);
char* pp_bandwidth_describe(struct pp_flow *flow_ctx);
void pp_bandwidth_init(uint32_t idx, struct pp_flow *flow_ctx, enum PP_ANALYZER_MODES mode, uint32_t mode_val);
void pp_bandwidth_destroy(uint32_t idx, struct pp_flow *flow_ctx);

#endif /* __PP_BANDWIDTH */
