#define DEBUG

#include <pp_rtt.h>

enum PP_ANALYZER_ACTION pp_rtt_inspect(uint32_t idx, struct pp_packet_context *pkt_ctx, struct pp_flow *flow_ctx) {

    if(pkt_ctx->protocols[PP_OSI_LAYER_4] == IPPROTO_TCP)
    {
        struct __pp_rtt_data *data = pp_analyzer_storage_get_next_location(idx, pkt_ctx, flow_ctx);

        if (likely(data)) {
            data->syn      = pkt_ctx->l4_meta.tcp.syn;       /* used to detect the inital sequence number (seq=0)' */
            data->fin      = pkt_ctx->l4_meta.tcp.fin;       /* used to detect end of connection */
            data->ack      = pkt_ctx->l4_meta.tcp.ack;
            data->seq_num  = pkt_ctx->l4_meta.tcp.seq_num;
            data->ack_num  = pkt_ctx->l4_meta.tcp.ack_num;
            data->size     = pkt_ctx->length - (pkt_ctx->l4_meta.tcp.hl + pkt_ctx->offsets[PP_OSI_LAYER_4]);
        }
    }
    else printf("dropped!");
    return PP_ANALYZER_ACTION_NONE;
}
/**
 * @brief private analyzer callback called with analyzers data related to the given flow
 * @param data ptr to the collected data
 * @param ts timestamp of the data set
 * @param direction the associated packet was captured
 */
static void __pp_rtt_analyze(void *data, uint64_t ts, int direction) {

    struct __pp_rtt_data *rtt_data      = data;
    static uint32_t initial_seq_no_up   = 0;
    static uint32_t initial_seq_no_down = 0;
    static uint32_t current_ack_up      = 0;
    static uint32_t current_ack_down    = 0;
    static struct __packet sin_packet;
    static struct __packet fin_packet;

    uint32_t current_seq = 0;

    packet_type type = check_package_type(rtt_data);

    switch(type)
    {
        case PKT_SYN:
        case PKT_ACK_SYN:
        {
            /* handle connection establishment */
            switch(direction)
            {
                case PP_PKT_DIR_DOWNSTREAM:
                    printf("SYN\t\\/\t");
                    initial_seq_no_down = rtt_data->seq_num;
                break;

                case PP_PKT_DIR_UPSTREAM:
                    printf("SYN\t/\\\t");
                    initial_seq_no_up = rtt_data->seq_num;
                break;

                default:
                    #ifdef DEBUG
                    printf("%s Invalid packet direction!!\n", RTT_DEBUG_TAG);
                    #endif
                break;
            }
            if(type == PKT_ACK_SYN)
            {
                report_new_rtt(ts - sin_packet.timestamp,ts,direction);
                add_new_package(1, 0, 0, 0, ts, direction);
            }
            else
            {
                sin_packet.timestamp = ts;
            }
        }
        break;

        case PKT_FIN:
        {
            printf("FIN\t");
            /* Handle connection closure */
            if(fin_packet.seq == (rtt_data->ack_num))
            {
                report_new_rtt(ts - fin_packet.timestamp, ts,direction);
            }
            else
            {
                fin_packet.timestamp = ts;
                fin_packet.seq       = rtt_data->seq_num + 1;
            }
        }
        break;

        case PKT_ACK:
        {
             /* Handle Acknowledgements */
            switch(direction)
            {
                case PP_PKT_DIR_DOWNSTREAM:
                {
                    printf("ACK\t\\/\t");
                    current_ack_down = rtt_data->ack_num - initial_seq_no_up;

                    if(upstream_packages.size > 0)
                    {
                        uint32_t target_ack = upstream_packages.first->seq + upstream_packages.first->length;

                        /* synchronize with packet-stream */
                        while(upstream_packages.first != upstream_packages.last &&
                              current_ack_down        != target_ack)
                        {
                            printf("first seq=%d, last seq=%d\n", upstream_packages.first->seq, upstream_packages.last->seq);
                            upstream_packages.first = upstream_packages.first + 1;
                        }
                        printf("down: Checking %d against %d", current_ack_down, target_ack);


                        /* we have found a match, report! */
                        if(current_ack_down == (upstream_packages.first->seq + upstream_packages.first->length))
                        {
                            report_new_rtt(ts - upstream_packages.first->timestamp, ts,direction);
                            target_ack = upstream_packages.first->seq + upstream_packages.first->length;
                        }

                        /* we have just processed the last element in our queue, time to clean up! */
                        if(upstream_packages.first == upstream_packages.last)
                        {
                            p_last_n_packages empty = {0};
                            upstream_packages       = empty;
                            //~ free(upstream_packages.packages);
                            //~ upstream_packages.packages = NULL;
                            //~ upstream_packages.size     = 0;
                        }
                    }
                }
                break;

                case PP_PKT_DIR_UPSTREAM:
                {
                    printf("ACK\t/\\\t");
                    current_ack_up = rtt_data->ack_num - initial_seq_no_down;
                    if(downstream_packages.size > 0)
                    {
                        uint32_t target_ack = downstream_packages.first->seq + downstream_packages.first->length;

                        /* synchronize with packet-stream */
                        while(downstream_packages.first != downstream_packages.last &&
                              current_ack_up          != target_ack)
                        {
                            downstream_packages.first = downstream_packages.first + 1;
                            target_ack = downstream_packages.first->seq + downstream_packages.first->length;
                        }
                        printf("up: Checking %d against %d", current_ack_up, target_ack);

                        /* we have found a match, report! */
                        if(current_ack_up == (downstream_packages.first->seq + downstream_packages.first->length))
                        {
                            report_new_rtt(ts - downstream_packages.first->timestamp, ts,direction);
                        }

                        /* we have just processed the last element in our queue, time to clean up! */
                        if(downstream_packages.first == downstream_packages.last)
                        {
                            p_last_n_packages empty = {0};
                            downstream_packages     = empty;
                            //~ free(downstream_packages.packages);
                            //~ downstream_packages.packages = NULL;
                            //~ downstream_packages.size     = 0;
                        }
                    }
                }
                break;

                default:
                    #ifdef DEBUG
                    printf("%s Invalid packet direction!!\n", RTT_DEBUG_TAG);
                    #endif
                break;
            }
        }
        break;

        case PKT_DATA:
        {
            /* Handle Data Packages */
            switch(direction)
            {
                case PP_PKT_DIR_DOWNSTREAM:
                {
                    printf("DATA\t\\/\t");
                    current_seq = rtt_data->seq_num - initial_seq_no_down;
                    printf("New Downstream-Package, seq(%d), size(%d)",current_seq, rtt_data->size);
                }
                break;

                case PP_PKT_DIR_UPSTREAM:
                {
                    printf("DATA\t/\\\t");
                    current_seq = rtt_data->seq_num - initial_seq_no_up;
                    printf("New Upstream-Package, seq(%d), size(%d)",current_seq, rtt_data->size);
                }
                break;

                default:
                    #ifdef DEBUG
                    printf("%s Invalid packet direction!!\n", RTT_DEBUG_TAG);
                    #endif
                    return;
                break;
            }

            add_new_package(current_seq, 0, 0, rtt_data->size, ts, direction);
        }
        break;

        default:
        break;
    }
    printf("\n");
}

inline packet_type check_package_type(struct __pp_rtt_data *_packet_data)
{
    if(_packet_data->syn == 1 && _packet_data->ack == 1)
    {
       return PKT_ACK_SYN;
    }

    if(_packet_data->syn == 1)
    {
        return PKT_SYN;
    }

    if(_packet_data->fin == 1)
    {
       return PKT_FIN;
    }

    if(_packet_data->size == 0 && _packet_data->ack != 0)
    {
        return PKT_ACK;
    }

    return PKT_DATA;
}

inline void add_new_package(uint32_t _seq,
                            uint32_t _ack,
                            uint16_t _syn,
                            uint16_t _length,
                            uint64_t _timestamp,
                            int _direction)
{
    struct __packet newPkt;
        newPkt.ack       = _ack;
        newPkt.seq       = _seq;
        newPkt.syn       = _syn;
        newPkt.length    = _length;
        newPkt.timestamp = _timestamp;

    switch(_direction)
    {
        case PP_PKT_DIR_UPSTREAM:
            upstream_packages.packages = realloc(upstream_packages.packages,
                                                (upstream_packages.size + 1) * sizeof(struct __packet));

            upstream_packages.packages[upstream_packages.size] = newPkt;

            upstream_packages.last = &upstream_packages.packages[upstream_packages.size];

            if(upstream_packages.size == 0)
            {
                upstream_packages.first = &upstream_packages.packages[0];
            }
            upstream_packages.size++;
        break;

        case PP_PKT_DIR_DOWNSTREAM:
            downstream_packages.packages = realloc(downstream_packages.packages,
                                                (downstream_packages.size + 1) * sizeof(struct __packet));

            downstream_packages.packages[downstream_packages.size] = newPkt;

            downstream_packages.last = &downstream_packages.packages[downstream_packages.size];

            if(downstream_packages.size == 0)
            {
                downstream_packages.first = &downstream_packages.packages[0];
            }
            downstream_packages.size++;
        break;
        default:
            #ifdef DEBUG
            printf("%s Invalid packet direction!!\n", RTT_DEBUG_TAG);
            #endif
        break;
    }
}

inline void report_new_rtt(uint64_t _rtt, uint64_t _ts, int _direction)
{
    switch(_direction)
    {
        case PP_PKT_DIR_UPSTREAM:
            pp_rtt_report_data.data_upstream = realloc(pp_rtt_report_data.data_upstream,
                                               (pp_rtt_report_data.size_up + 1) * sizeof(struct __pp_rtt_report_data));
            pp_rtt_report_data.data_upstream[pp_rtt_report_data.size_up].rtt       = _rtt;
            pp_rtt_report_data.data_upstream[pp_rtt_report_data.size_up].timestamp = _ts;
            pp_rtt_report_data.size_up++;
        break;

        case PP_PKT_DIR_DOWNSTREAM:
            pp_rtt_report_data.data_downstream = realloc(pp_rtt_report_data.data_downstream,
                                               (pp_rtt_report_data.size_down + 1) * sizeof(struct __pp_rtt_report_data));
            pp_rtt_report_data.data_downstream[pp_rtt_report_data.size_down].rtt       = _rtt;
            pp_rtt_report_data.data_downstream[pp_rtt_report_data.size_down].timestamp = _ts;
            pp_rtt_report_data.size_down++;
        break;

        default:
            #ifdef DEBUG
            printf("%s Invalid packet direction!!\n", RTT_DEBUG_TAG);
            #endif
        break;

    }
}

/* analyse function */
void pp_rtt_analyze(uint32_t idx, struct pp_flow *flow_ctx) {
    free(pp_rtt_report_data.data_upstream);
    pp_rtt_report_data.data_upstream = NULL;
    pp_rtt_report_data.size_up = 0;

    free(pp_rtt_report_data.data_downstream);
    pp_rtt_report_data.data_downstream = NULL;
    pp_rtt_report_data.size_down = 0;

    free(upstream_packages.packages);
    upstream_packages.packages = NULL;
    upstream_packages.size     = 0;

    free(downstream_packages.packages);
    downstream_packages.packages = NULL;
    downstream_packages.size     = 0;

    pp_analyzer_callback_for_each_entry(idx, flow_ctx, &__pp_rtt_analyze);
}

/* report function */
char* pp_rtt_report(uint32_t idx, struct pp_flow *flow_ctx) {
    /* TODO: transform to rest output if rest backend is enabled */

    if((pp_rtt_report_data.size_up + pp_rtt_report_data.size_down)  > RTT_ANALYZER_MIN_SAMPLE_COUNT) {
        int i;
        char buf[16000] = {'\0'};
        int wpos = 0;

        wpos += sprintf(buf, "{");
        for (i = 0; i < pp_rtt_report_data.size_up; i++) {
            wpos += sprintf(&buf[wpos], "{Upstream:\tTS:%" PRIu64 ",\trtt:%d},\n", pp_rtt_report_data.data_upstream[i].timestamp,
                                                                           pp_rtt_report_data.data_upstream[i].rtt);
        }
        for (i = 0; i < pp_rtt_report_data.size_down; i++) {
            wpos += sprintf(&buf[wpos], "{Downstream:\tTS:%" PRIu64 ",\trtt:%d},\n", pp_rtt_report_data.data_downstream[i].timestamp,
                                                                           pp_rtt_report_data.data_downstream[i].rtt);
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
char* pp_rtt_describe(void) {

    /* TODO */
    return strdup("This analyzers measures the Round-Trip-Time (RTT) of a given packet stream.");
}

/* init private data */
void pp_rtt_init(uint32_t idx, struct pp_flow *flow_ctx, enum PP_ANALYZER_MODES mode, uint32_t mode_val) {

    PP_ANALYZER_STORE_INIT(pp_rtt, idx, flow_ctx, mode, mode_val);

    pp_rtt_report_data.data_upstream = NULL;
    pp_rtt_report_data.size_up = 0;
    pp_rtt_report_data.data_downstream = NULL;
    pp_rtt_report_data.size_down = 0;

    upstream_packages.packages   = NULL;
    upstream_packages.size       = 0;
    downstream_packages.packages = NULL;
    downstream_packages.size     = 0;
}

/* free all data */
void pp_rtt_destroy(uint32_t idx, struct pp_flow *flow_ctx) {

    free(pp_rtt_report_data.data_upstream);
    pp_rtt_report_data.data_upstream = NULL;
    pp_rtt_report_data.size_up = 0;

    free(pp_rtt_report_data.data_downstream);
    pp_rtt_report_data.data_downstream = NULL;
    pp_rtt_report_data.size_down = 0;

    free(upstream_packages.packages);
    upstream_packages.packages = NULL;
    upstream_packages.size     = 0;

    free(downstream_packages.packages);
    downstream_packages.packages = NULL;
    downstream_packages.size     = 0;

    /* free analyzer data */
    pp_analyzer_storage_destroy(idx, flow_ctx);
}


/* return unique analyzer db id */
uint32_t pp_rtt_id(void) {
	return PP_RTT_ANALYZER_DB_ID;
}
