#ifndef __PP_ANALYSER
#define __PP_ANALYSER

#include <pp_decap.h>
#include <pp_flow.h>

/**
 * each analyser is invoked on each packet
 *
 *
 * the describe function must deliver a JSON string that contains the
 * description of the analyser according XXXXX TODO
 */

enum PP_ANALYSER_MODES {
	PP_ANALYSER_MODE_UNKNOWN = 0,
	/* keep all collected data (may conusme all available memory) */
	PP_ANALYSER_MODE_INFINITY,
	/* only keep collected data within given timestamp
	 * time given in milliseconds
	 */
	PP_ANALYSER_MODE_TIMESPAN,
	/* only keep collected data for last PACKETCOUNT packets */
	PP_ANALYSER_MODE_PACKETCOUNT,
	PP_ANALYSER_MODE_EOL
};

struct pp_analyser {

	/* analyser index - references the data entry inside of the flow */
	uint32_t idx;

	/* collect data function */
	void (*collect)(uint32_t idx,struct pp_packet_context *pkt_ctx, struct pp_flow *flow_ctx);

	/* analyse function */
	void (*analyse)(uint32_t idx,struct pp_flow *flow_ctx);

	/* report function */
	char* (*report)(uint32_t idx,struct pp_flow *flow_ctx);

	/* self description function */
	char* (*describe)(struct pp_flow *flow_ctx);

	/* init function */
	void (*init)(uint32_t idx,struct pp_flow *flow_ctx, enum PP_ANALYSER_MODES mode, uint32_t mode_val);

	/* cleanup function */
	void (*destroy)(uint32_t idx,struct pp_flow *flow_ctx);

	/* holds analyser specific data */
	void *usr_ptr;

	/* point to the next analyser in the chain */
	struct pp_analyser *next_analyser;
};

int pp_register_analyser(struct pp_analyser **analyser_list,
						 void (*collect)(uint32_t idx, struct pp_packet_context *pkt_ctx, struct pp_flow *flow_ctx),
						 void (*analyse)(uint32_t idx, struct pp_flow *flow_ctx),
						 char* (*report)(uint32_t idx, struct pp_flow *flow_ctx),
						 char* (*describe)(struct pp_flow *flow_ctx),
						 void (*init)(uint32_t idx, struct pp_flow *flow_ctx, enum PP_ANALYSER_MODES mode, uint32_t mode_val),
						 void (*destroy)(uint32_t idx, struct pp_flow *flow_ctx),
						 void *usr_ptr);


#endif /* __PP_ANALYSER */
