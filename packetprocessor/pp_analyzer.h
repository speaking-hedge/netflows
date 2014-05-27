#ifndef __PP_analyzer
#define __PP_analyzer

#include <pp_decap.h>
#include <pp_flow.h>

/**
 * each analyzer is invoked on each packet
 *
 *
 * the describe function must deliver a JSON string that contains the
 * description of the analyzer according XXXXX TODO
 */

enum PP_ANALYZER_MODES {
	PP_ANALYZER_MODE_UNKNOWN = 0,
	/* keep all collected data (may conusme all available memory) */
	PP_ANALYZER_MODE_INFINITY,
	/* only keep collected data within given timestamp
	 * time given in milliseconds
	 */
	PP_ANALYZER_MODE_TIMESPAN,
	/* only keep collected data for last PACKETCOUNT packets */
	PP_ANALYZER_MODE_PACKETCOUNT,
	PP_ANALYZER_MODE_EOL
};

struct pp_analyzer {

	/* analyzer index - references the data entry inside of the flow */
	uint32_t idx;

	/* collect data function */
	void (*collect)(uint32_t idx,struct pp_packet_context *pkt_ctx, struct pp_flow *flow_ctx);

	/* analyze function */
	void (*analyze)(uint32_t idx,struct pp_flow *flow_ctx);

	/* report function */
	char* (*report)(uint32_t idx,struct pp_flow *flow_ctx);

	/* self description function */
	char* (*describe)(struct pp_flow *flow_ctx);

	/* init function */
	void (*init)(uint32_t idx,struct pp_flow *flow_ctx, enum PP_ANALYZER_MODES mode, uint32_t mode_val);

	/* cleanup function */
	void (*destroy)(uint32_t idx,struct pp_flow *flow_ctx);

	/* holds analyzer specific data */
	void *usr_ptr;

	/* point to the next analyzer in the chain */
	struct pp_analyzer *next_analyzer;
};

int pp_analyzer_register(struct pp_analyzer **analyzer_list,
						 void (*collect)(uint32_t idx, struct pp_packet_context *pkt_ctx, struct pp_flow *flow_ctx),
						 void (*analyze)(uint32_t idx, struct pp_flow *flow_ctx),
						 char* (*report)(uint32_t idx, struct pp_flow *flow_ctx),
						 char* (*describe)(struct pp_flow *flow_ctx),
						 void (*init)(uint32_t idx, struct pp_flow *flow_ctx, enum PP_ANALYZER_MODES mode, uint32_t mode_val),
						 void (*destroy)(uint32_t idx, struct pp_flow *flow_ctx),
						 void *usr_ptr);

/**************************************************************/
/* macros and functions for analyzer independent data storage */
/**************************************************************/

/* take memory in chunks of slot-step elements */
#define PP_ANALYZER_SLOT_STEP	100

/* macro to greate analyzer storage struct */
#define PP_ANALYZER_STORE_CREATE(ANALYZER_NAME, DATATYPE) \
struct ANALYZER_NAME { \
	enum PP_ANALYZER_MODES mode;  \
	uint32_t mode_val; \
	uint32_t slot_size; \
	uint64_t write_pos; \
	uint32_t available_slots; \
	uint32_t used_slots; \
	struct ANALYZER_NAME ## _data { \
		uint64_t timestamp; \
		uint8_t direction; \
		struct ANALYZER_NAME ## _data *next; \
		/* keep analyzer related parts below this line */ \
		DATATYPE data; \
	} *entries; \
	struct ANALYZER_NAME ## _data *head_entry; \
	struct ANALYZER_NAME ## _data *tail_entry; \
};

/* create a dummy struct that can be used to access the generic attributes */
PP_ANALYZER_STORE_CREATE(pp_analyzer_store_void, void*);

#define ptr_struct_member_size(type) sizeof(*((struct type *)0)->entries)

/* macro to init an analyzer specific storage inside of a given flow */
#define PP_ANALYZER_STORE_INIT(ANALYZER_NAME, ANALYZER_INDEX, FLOW, MODE, MODE_VAL) pp_analyzer_storage_init_int(ANALYZER_INDEX, FLOW, ptr_struct_member_size(ANALYZER_NAME), MODE, MODE_VAL)
int pp_analyzer_storage_init_int(uint32_t idx, struct pp_flow *flow_ctx, int slot_size, uint32_t mode, int mode_val);

void* pp_analyzer_storage_get_next_location(uint32_t idx, struct pp_packet_context *pkt_ctx, struct pp_flow *flow_ctx);

int pp_analyzer_callback_for_each_entry(uint32_t idx, struct pp_flow *flow_ctx, void (*fnct)(void* entry, uint64_t ts, int direction));

void pp_analyzer_storage_destroy(uint32_t idx, struct pp_flow *flow_ctx);



#endif /* __PP_analyzer */
