#include <pp_analyser.h>

/**
 * @brief add a new analyser to the chain of analysers
 * @param pp_ctx to add the analyser to
 * @param analyse function to be run on each packet
 * @param report function that generates the report based on collected data
 * @param describe funtion that delivers an analyser description
 * @param init funtion to be called before the first packet of the flow is analysed
 * @param destroy funtion to clean up all data used by the analyser on that flow
 * @param usr_ptr to store user data into (can be NULL)
 * @retval 0 on success
 * @retval 1 on error
 */
int pp_register_analyser(struct pp_analyser **analyser_list,
						 void (*collect)(uint32_t idx, struct pp_packet_context *pkt_ctx, struct pp_flow *flow_ctx),
						 void (*analyse)(uint32_t idx, struct pp_flow *flow_ctx),
						 char* (*report)(uint32_t idx, struct pp_flow *flow_ctx),
						 char* (*describe)(struct pp_flow *flow_ctx),
						 void (*init)(uint32_t idx, struct pp_flow *flow_ctx, enum PP_ANALYSER_MODES mode, uint32_t mode_val),
						 void (*destroy)(uint32_t idx, struct pp_flow *flow_ctx),
						 void *usr_ptr) {

	struct pp_analyser *new_analyser = NULL;
	static int analyser_idx = 0;

	if (!(new_analyser = malloc(sizeof(struct pp_analyser)))) {
		return 1;
	}

	new_analyser->collect = collect;
	new_analyser->analyse = analyse;
	new_analyser->report = report;
	new_analyser->describe = describe;
	new_analyser->init = init;
	new_analyser->destroy = destroy;
	new_analyser->next_analyser = NULL;
	new_analyser->idx = analyser_idx++;

	if (!analyser_list) {
		*analyser_list = new_analyser;
	} else {
		new_analyser->next_analyser = *analyser_list;
		*analyser_list = new_analyser;
	}

	return 0;
}
