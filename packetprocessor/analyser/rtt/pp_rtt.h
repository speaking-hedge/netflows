#include <pp_analyzer.h>
#include <pp_flow.h>
//#include <queue.h>

/* unique database id */
#define PP_RTT_ANALYZER_DB_ID			3

/* number of statistic entries we need to generate a reliable report */
#define RTT_ANALYZER_MIN_SAMPLE_COUNT   1

/* window size analyser specific data */
struct __pp_rtt_data {
    uint32_t seq_num;
    uint32_t ack_num;
    uint32_t ack;
    uint16_t syn;
    uint16_t fin;
    uint16_t size;
};

struct __pp_rtt_report_data {
        uint64_t rtt;
        uint64_t timestamp;
} __pp_rtt_report_data;

static struct {
    struct __pp_rtt_report_data *data_upstream;
    struct __pp_rtt_report_data *data_downstream;

    uint32_t size_up;
    uint32_t size_down;
} pp_rtt_report_data;

typedef struct p_last_n_packages{
    struct __packet {
        uint32_t seq;
        uint32_t ack;
        uint16_t syn;
        uint16_t length;
        uint64_t timestamp;
    } *packages;
    uint32_t size;
    struct __packet *first;
    struct __packet *last;
} p_last_n_packages;

typedef enum packet_type{
    PKT_SYN = 0,
    PKT_ACK_SYN,
    PKT_FIN,
    PKT_ACK,
    PKT_DATA
}packet_type;

static p_last_n_packages upstream_packages;
static p_last_n_packages downstream_packages;

static const char *RTT_DEBUG_TAG = "[pp_rtt_analyzer]";

/* create storage struct*/
PP_ANALYZER_STORE_CREATE(pp_rtt, struct __pp_rtt_data);

enum PP_ANALYZER_ACTION pp_rtt_inspect(uint32_t idx, struct pp_packet_context *pkt_ctx, struct pp_flow *flow_ctx);
void pp_rtt_analyze(uint32_t idx, struct pp_flow *flow_ctx);
char* pp_rtt_report(uint32_t idx, struct pp_flow *flow_ctx);
char* pp_rtt_describe(void);
void pp_rtt_init(uint32_t idx, struct pp_flow *flow_ctx, enum PP_ANALYZER_MODES mode, uint32_t mode_val);
void pp_rtt_destroy(uint32_t idx, struct pp_flow *flow_ctx);
inline void report_new_rtt(uint64_t _rtt, uint64_t _ts, int _direction);
inline void add_new_package(uint32_t _seq,uint32_t _ack,uint16_t _syn,uint16_t _length,uint64_t _timestamp,int _direction);
inline packet_type check_package_type(struct __pp_rtt_data *rtt_data);
uint32_t pp_rtt_id(void);
