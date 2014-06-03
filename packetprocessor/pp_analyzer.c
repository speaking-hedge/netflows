#include <pp_analyzer.h>

/**
 * @brief add a new analyzer to the chain of analyzers
 * @param pp_ctx to add the analyzer to
 * @param analyze function to be run on each packet
 * @param report function that generates the report based on collected data
 * @param describe funtion that delivers an analyzer description
 * @param init funtion to be called before the first packet of the flow is analyzed
 * @param destroy funtion to clean up all data used by the analyzer on that flow
 * @param usr_ptr to store user data into (can be NULL)
 * @retval 0 on success
 * @retval EADDRINUSE if the analyzer was already registered
 * @retval ENOMEM if there was a problem during init
 */
int pp_analyzer_register(struct pp_analyzer **analyzer_list,
						 enum PP_ANALYZER_ACTION (*inspect)(uint32_t idx, struct pp_packet_context *pkt_ctx, struct pp_flow *flow_ctx),
						 void (*analyze)(uint32_t idx, struct pp_flow *flow_ctx),
						 char* (*report)(uint32_t idx, struct pp_flow *flow_ctx),
						 char* (*describe)(void),
						 void (*init)(uint32_t idx, struct pp_flow *flow_ctx, enum PP_ANALYZER_MODES mode, uint32_t mode_val),
						 void (*destroy)(uint32_t idx, struct pp_flow *flow_ctx),
						 uint32_t (*id)(void),
						 void *usr_ptr) {

	struct pp_analyzer *new_analyzer = NULL, *cur = NULL;
	static int analyzer_idx = 0;

	if (*analyzer_list) {

		cur = *analyzer_list;

		while(cur) {
			if (cur->id() == id()) {
				return EADDRINUSE;
			}
			cur = cur->next_analyzer;
		}
	}

	if (!(new_analyzer = malloc(sizeof(struct pp_analyzer)))) {
		return ENOMEM;
	}

	new_analyzer->inspect = inspect;
	new_analyzer->analyze = analyze;
	new_analyzer->report = report;
	new_analyzer->describe = describe;
	new_analyzer->init = init;
	new_analyzer->destroy = destroy;
	new_analyzer->id = id;
	new_analyzer->usr_ptr = usr_ptr;

	new_analyzer->next_analyzer = NULL;
	new_analyzer->idx = analyzer_idx++;

	if (!analyzer_list) {
		*analyzer_list = new_analyzer;
	} else {
		new_analyzer->next_analyzer = *analyzer_list;
		*analyzer_list = new_analyzer;
	}

	return 0;
}

/**
 * @brief macro PP_ANALYZE_STORE_INIT to init the storage used by an analyzer
 * @note call within the init function of the analyzer
 * @param idx of the analyzer in the flows analyzer stack
 * @param flow_ctx the analyzer is attached to
 * @param bytes_per_entry size of the analyzer specific part of the entry
 * @param mode of the analyzer
 * @param mode_val settings for the analyzer mode (packet count / timespan in ms)
 * @retval 0 on success
 * @retval 1 on error
 */
int pp_analyzer_storage_init_int(uint32_t idx,
								 struct pp_flow *flow_ctx,
								 int bytes_per_entry,
								 enum PP_ANALYZER_MODES mode,
								 int mode_val) {

	struct pp_analyzer_store_void *generic_store = NULL;
	void *naked = NULL;
	int i = 0;

	/* create entry for the analyzer inside of the flow */
	if (!(generic_store = flow_ctx->analyzer_data[idx] = (struct pp_analyzer_store_void*) calloc(1, sizeof(struct pp_analyzer_store_void)))) {
		return 1;
	}

	generic_store->mode = mode;
	generic_store->mode_val = mode_val;
	generic_store->slot_size = bytes_per_entry;
	generic_store->write_pos = 0;
	generic_store->used_slots = 0;

	switch(generic_store->mode) {
	case PP_ANALYZER_MODE_PACKETCOUNT:
		/* reserve packet-count entries */
		if(!(generic_store->entries = calloc(bytes_per_entry, mode_val))) {
			free(flow_ctx->analyzer_data[idx]);
			flow_ctx->analyzer_data[idx] = NULL;
			return 1;
		}
		generic_store->available_slots = generic_store->mode_val;
		break;
	case PP_ANALYZER_MODE_INFINITY:
		/* start with PP_WINDOW_SIZE_SLOT_STEP elements */
		generic_store->entries = calloc(1, PP_ANALYZER_SLOT_STEP*bytes_per_entry);
		generic_store->available_slots = PP_ANALYZER_SLOT_STEP;
		break;
	case PP_ANALYZER_MODE_TIMESPAN:
		/* timespan is given in ms, packet times are in us */
		generic_store->mode_val *= 1000;
		generic_store->entries = calloc(PP_ANALYZER_SLOT_STEP, bytes_per_entry);
		generic_store->available_slots = PP_ANALYZER_SLOT_STEP;
		/* create a circular storage */
		naked = generic_store->entries;
		for (i = 0; i < (PP_ANALYZER_SLOT_STEP -  1); i++) {
			((struct pp_analyzer_store_void_data *)naked)->next = (naked + bytes_per_entry);
			naked = ((struct pp_analyzer_store_void_data *)naked)->next;
		}
		((struct pp_analyzer_store_void_data *)naked)->next = generic_store->entries;
		/* the first request accesses the first element in the ring */
		generic_store->head_entry = naked;
		generic_store->tail_entry = ((struct pp_analyzer_store_void_data *)naked)->next;
		generic_store->available_slots = PP_ANALYZER_SLOT_STEP;
		break;
	default:
		break;
	}

	return 0;
}

/**
 * @brief return a ptr where the data can be stored
 * @note just cast and assign your data, direction and timestamp is already assigned
 * @retval returns ptr to the data part of the next entry
 */
void* pp_analyzer_storage_get_next_location(uint32_t idx, struct pp_packet_context *pkt_ctx, struct pp_flow *flow_ctx) {

	struct pp_analyzer_store_void *generic_store = flow_ctx->analyzer_data[idx];
	void *naked = NULL;

	if (!generic_store) {
		return NULL;
	}

	switch(generic_store->mode) {
	case PP_ANALYZER_MODE_PACKETCOUNT:
		naked = generic_store->entries;
		naked += generic_store->slot_size * (generic_store->write_pos % generic_store->available_slots);

		((struct pp_analyzer_store_void_data *)naked)->timestamp = pkt_ctx->timestamp;
		((struct pp_analyzer_store_void_data *)naked)->direction = pkt_ctx->direction;
		generic_store->write_pos++;
		return &((struct pp_analyzer_store_void_data *)naked)->data;
	case PP_ANALYZER_MODE_INFINITY:
		/* get a new chunck of memory if we need some */
		if(generic_store->available_slots == generic_store->write_pos) {
			generic_store->available_slots += PP_ANALYZER_SLOT_STEP;
			generic_store->entries = realloc(generic_store->entries, generic_store->available_slots * generic_store->slot_size);
			if(!generic_store->entries) {
				generic_store->available_slots = 0;
				return NULL;
			}
		}
		naked = generic_store->entries;
		naked += (generic_store->slot_size * generic_store->write_pos);
		((struct pp_analyzer_store_void_data *)naked)->timestamp = pkt_ctx->timestamp;
		((struct pp_analyzer_store_void_data *)naked)->direction = pkt_ctx->direction;
		generic_store->write_pos++;
		return &((struct pp_analyzer_store_void_data *)naked)->data;
	case PP_ANALYZER_MODE_TIMESPAN:

		/* if the timespan between the new entry and the next entry is > then max_age,
		 * overwrite the next entry
		 */

		if (generic_store->used_slots < generic_store->available_slots) {
			/* fill the ringbuffer till all slots are used */
			generic_store->head_entry->next->timestamp = pkt_ctx->timestamp;
			generic_store->head_entry->next->direction = pkt_ctx->direction;
			naked = generic_store->head_entry->next;
			generic_store->head_entry = generic_store->head_entry->next;
			generic_store->write_pos++;
			generic_store->used_slots++;
			return &((struct pp_analyzer_store_void_data *)naked)->data;
		} else {
			/* overwrite or increase ring size */
			if (pkt_ctx->timestamp - generic_store->head_entry->next->timestamp > generic_store->mode_val) {
				/* overwrite next element cause it is older then mode_val */
				generic_store->head_entry->next->timestamp = pkt_ctx->timestamp;
				generic_store->head_entry->next->direction = pkt_ctx->direction;
				generic_store->tail_entry = generic_store->tail_entry->next;
				naked = generic_store->head_entry->next;
				generic_store->head_entry = generic_store->head_entry->next;
				generic_store->write_pos++;
				return &((struct pp_analyzer_store_void_data *)naked)->data;
			} else {
				/* insert a new element into the ring cause the next one
				 * has not reached the age limit yet.
				 *
				 * over the time the ring may grow and become partly unused.
				 * for now this is an accepted fact but we should think about
				 * a periodical/triggered clean up function...
				 */
				 if (!(naked = calloc(1, generic_store->slot_size))) {
					 return NULL;
				 }
				((struct pp_analyzer_store_void_data *)naked)->timestamp = pkt_ctx->timestamp;
				((struct pp_analyzer_store_void_data *)naked)->direction = pkt_ctx->direction;
				((struct pp_analyzer_store_void_data *)naked)->next = generic_store->head_entry->next;
				generic_store->head_entry->next = naked;
				generic_store->head_entry = naked;
				generic_store->write_pos++;
				generic_store->used_slots++;
				generic_store->available_slots++;
				return &((struct pp_analyzer_store_void_data *)naked)->data;
			}
		} /* __overwrite_or_insert_phase */
	default:
		break;
	} /* __switch_mode */
	return NULL;
}

/**
 * @brief call a function for each element collected in the buffer
 * @note the callback will get the elements in the chronological order of arrival (from the oldest to the newest)
 * if the analyzer mode is timespan, only elements fitting the timespan criteria are used
 * @param idx of the analyzer in the analyzer stack of the flow
 * @param flow_ctx to run the callback on
 * @param void (*fnct)(void* entry,ts,direction) callback to be invoced on each element
 * @retval >= 0 number of times the callback was invoked
 * @retval <0 on error
 */
int pp_analyzer_callback_for_each_entry(uint32_t idx, struct pp_flow *flow_ctx, void (*fnct)(void* entry, uint64_t ts, int direction)) {

	struct pp_analyzer_store_void *generic_store = flow_ctx->analyzer_data[idx];
	void *naked = NULL;
	int i = 0, c = 0;
	uint64_t ts_youngest;

	assert(fnct);

	if (!generic_store) {
		return -1;
	}

	if (generic_store->write_pos == 0) {
		return 0;
	}

	switch(generic_store->mode) {
	case PP_ANALYZER_MODE_PACKETCOUNT:
		if ((generic_store->write_pos - 1) < generic_store->available_slots) {
			for (i = 0; i < generic_store->write_pos; i++) {
				naked = generic_store->entries;
				naked += (i * generic_store->slot_size);
				/* TODO: remove
				 * printf("%s\n", pp_packet_direction2strlong(((struct pp_analyzer_store_void_data*)naked)->direction));
				 */
				fnct(&((struct pp_analyzer_store_void_data *)naked)->data,
					 ((struct pp_analyzer_store_void_data*)naked)->timestamp,
					 ((struct pp_analyzer_store_void_data*)naked)->direction);
				c++;
			}
		} else {
			/* start in between */
			for (i = (generic_store->write_pos % generic_store->available_slots); i < generic_store->available_slots; i++) {
				naked = generic_store->entries;
				naked += (i * generic_store->slot_size);
				fnct(&((struct pp_analyzer_store_void_data *)naked)->data,
					 ((struct pp_analyzer_store_void_data*)naked)->timestamp,
					 ((struct pp_analyzer_store_void_data*)naked)->direction);
			}
			for (i = 0; i < generic_store->write_pos % generic_store->available_slots; i++) {
				naked = generic_store->entries;
				naked += (i * generic_store->slot_size);
				fnct(&((struct pp_analyzer_store_void_data *)naked)->data,
					 ((struct pp_analyzer_store_void_data*)naked)->timestamp,
					 ((struct pp_analyzer_store_void_data*)naked)->direction);
			}
			c = generic_store->available_slots;
		}
		return c;
	case PP_ANALYZER_MODE_INFINITY:
		for (i = 0; i < generic_store->write_pos; i++) {
			naked = generic_store->entries;
			naked += (i * generic_store->slot_size);
			fnct(&((struct pp_analyzer_store_void_data *)naked)->data,
				 ((struct pp_analyzer_store_void_data*)naked)->timestamp,
				 ((struct pp_analyzer_store_void_data*)naked)->direction);
			c++;
		}
		return c;

	case PP_ANALYZER_MODE_TIMESPAN:
		ts_youngest = generic_store->head_entry->timestamp;
		naked = generic_store->tail_entry;

		do {
			/* callback for all entries within accepted age */
			if (ts_youngest - ((struct pp_analyzer_store_void_data *)naked)->timestamp <= generic_store->mode_val) {
				fnct(&((struct pp_analyzer_store_void_data *)naked)->data,
					((struct pp_analyzer_store_void_data*)naked)->timestamp,
					((struct pp_analyzer_store_void_data*)naked)->direction);
				c++;
			}
			naked = ((struct pp_analyzer_store_void_data *)naked)->next;
		} while (naked != generic_store->head_entry);
		fnct(&((struct pp_analyzer_store_void_data*)generic_store->head_entry)->data,
			((struct pp_analyzer_store_void_data*)generic_store->head_entry)->timestamp,
			((struct pp_analyzer_store_void_data*)generic_store->head_entry)->direction);
		return ++c;
	default:
		break;
	}
	return -1;
}

/**
 * @brief free storage used by analyzer
 * @param idx of the analyzer in the analyzer stack of the flow
 * @param flow_ctx to destroy the storage for
 */
void pp_analyzer_storage_destroy(uint32_t idx, struct pp_flow *flow_ctx) {

	struct pp_analyzer_store_void *generic_store = flow_ctx->analyzer_data[idx];

	free(generic_store->entries);
	generic_store->entries = NULL;

	generic_store->mode = PP_ANALYZER_MODE_UNKNOWN;
	generic_store->mode_val = 0;
	generic_store->slot_size = 0;
	generic_store->write_pos = 0;
	generic_store->used_slots = 0;

	free(flow_ctx->analyzer_data[idx]);
	flow_ctx->analyzer_data[idx] = NULL;
}
