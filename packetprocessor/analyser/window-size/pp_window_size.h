#include <pp_analyzer.h>
#include <pp_flow.h>

/* unique database id */
#define PP_WINDOW_SIZE_ANALYZER_DB_ID	2

/* number of statistic entries we need to generate a reliable report */
#define WINDOWS_SIZE_ANALYZER_MIN_SAMPLE_COUNT  100

/* window size analyser specific data */
struct __pp_window_size_data {
    uint16_t size;
};

static struct {
    struct __pp_window_size_report_data {
        uint16_t window_size_upstream;
        uint16_t window_size_downstream;
        uint64_t timestamp;
    } *data;
    uint32_t size;
} pp_window_size_report_data;

/* create storage struct*/
PP_ANALYZER_STORE_CREATE(pp_window_size, struct __pp_window_size_data);

enum PP_ANALYZER_ACTION pp_window_size_inspect(uint32_t idx, struct pp_packet_context *pkt_ctx, struct pp_flow *flow_ctx);
void pp_window_size_analyze(uint32_t idx, struct pp_flow *flow_ctx);
char* pp_window_size_report(uint32_t idx, struct pp_flow *flow_ctx);
char* pp_window_size_describe(void);
void pp_window_size_init(uint32_t idx, struct pp_flow *flow_ctx, enum PP_ANALYZER_MODES mode, uint32_t mode_val);
void pp_window_size_destroy(uint32_t idx, struct pp_flow *flow_ctx);
uint32_t pp_window_size_id(void);
