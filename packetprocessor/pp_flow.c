#include <pp_flow.h>

static inline uint32_t __pp_thomas_wang_hash32(uint32_t a);
static inline void __pp_flow_update(struct pp_flow *flow, struct pp_packet_context *pkt_ctx);

/* from pp_fnct */
extern int pp_get_proto_name(uint layer, uint32_t protocol, char* buf, size_t buf_len);

/**
 * @brief fast hash function by Thomas Wang
 * @note: see http://burtleburtle.net/bob/hash/integer.html
 * (as http://www.concentric.net/~ttwang/tech/inthash.htm seems to be down)
 * @param a key to create a hash on
 * @retval hash
 */
static inline uint32_t __pp_thomas_wang_hash32(uint32_t a) {
	a = (a ^ 61) ^ (a >> 16);
	a = a + (a << 3);
	a = a ^ (a >> 4);
	a = a * 0x27d4eb2d;
	a = a ^ (a >> 15);
	return a;
}

/**
 * @brief create an empty hash table
 * @param size number of buckets in the table
 * @param flow_delete_fntc is executed if a flow is removed from the table
 * @param hash_fnct to be used
 * @retval ptr to the flow table
 * @retval NULL on error
 */
struct pp_flow_table* pp_flow_table_create(uint32_t size,
										   void (*flow_delete_fntc)(struct pp_flow*),
										   uint32_t (*hash_fnct)(uint32_t key)) {

	struct pp_flow_table *table = NULL;

	if (!(table = calloc(1, sizeof(struct pp_flow_table)))) {
		return NULL;
	}

	table->size = size;
	if (!(table->buckets = calloc(PP_FLOW_HASH_TABLE_BUCKETS, sizeof(__typeof__(table->buckets))))) {
		free(table);
		return NULL;
	}

	table->flow_delete_fntc = flow_delete_fntc;

	if (hash_fnct) {
		table->hash_fnct = hash_fnct;
	} else {
		table->hash_fnct = &__pp_thomas_wang_hash32;
	}

	return table;
}

/**
 * @brief update flow using data from packet context
 * @note also sets the packet direction in pkt_ctx
 * @param flow points to the flow to be updated
 * @param pkt_ctx points to the packet used for the update
 */
static inline void __pp_flow_update(struct pp_flow *flow, struct pp_packet_context *pkt_ctx) {

	pthread_mutex_lock(&flow->lock);

	flow->last_seen = pkt_ctx->timestamp;

	if (memcmp(&flow->ep_a.ip.addr.v6, &pkt_ctx->src_addr.v6, sizeof(pkt_ctx->src_addr.v6))) {
		/* upstream */
		flow->data_upstream.packets++;
		flow->data_upstream.bytes += pkt_ctx->length;
		pkt_ctx->direction = PP_PKT_DIR_UPSTREAM;
	} else {
		/* downstream */
		flow->data_downstream.packets++;
		flow->data_downstream.bytes += pkt_ctx->length;
		pkt_ctx->direction = PP_PKT_DIR_DOWNSTREAM;
	}
	flow->data_cum.packets++;
	flow->data_cum.bytes += pkt_ctx->length;

	pthread_mutex_unlock(&flow->lock);
}

/**
 * @brief compare flow with packet context
 * @note compare src/dst ip and port
 * @retval 0 if flow is equal to packet_ctx
 * @retval 1 if unequal
 */
static inline int __pp_flow_table_compare(struct pp_flow *flow,
											struct pp_packet_context *pkt_ctx) {

	if (flow->protocols[PP_OSI_LAYER_3] != pkt_ctx->protocols[PP_OSI_LAYER_3] ||
		flow->protocols[PP_OSI_LAYER_4] != pkt_ctx->protocols[PP_OSI_LAYER_4]) {
			return 1;
	}

	/* less expensive port check first */
	if ((flow->ep_a.port != pkt_ctx->src_port ||
		flow->ep_b.port != pkt_ctx->dst_port) &&
		(flow->ep_a.port != pkt_ctx->dst_port ||
		flow->ep_b.port != pkt_ctx->src_port)) {
		return 1;
	}

	switch(flow->protocols[PP_OSI_LAYER_3]) {
	case ETH_P_IP:
		if ( (flow->ep_a.ip.addr.v4.s_addr != pkt_ctx->src_addr.v4.s_addr ||
			  flow->ep_b.ip.addr.v4.s_addr != pkt_ctx->dst_addr.v4.s_addr) &&
			  (flow->ep_a.ip.addr.v4.s_addr != pkt_ctx->dst_addr.v4.s_addr ||
			  flow->ep_b.ip.addr.v4.s_addr != pkt_ctx->src_addr.v4.s_addr)) {
				  return 1;
		}
		break;
	case ETH_P_IPV6:
		if ( (!IN6_ARE_ADDR_EQUAL(&flow->ep_a.ip.addr.v6, &pkt_ctx->src_addr.v6) ||
			  !IN6_ARE_ADDR_EQUAL(&flow->ep_b.ip.addr.v6, &pkt_ctx->dst_addr.v6)) &&
			 (!IN6_ARE_ADDR_EQUAL(&flow->ep_a.ip.addr.v6, &pkt_ctx->dst_addr.v6) ||
			  !IN6_ARE_ADDR_EQUAL(&flow->ep_b.ip.addr.v6, &pkt_ctx->src_addr.v6))) {
				  return 1;
		}
		break;
	default:
		return 1;
	}

	return 0;
}

/**
 * @brief construct flow object from packet context
 * @param pkt_ctx contains packet informations
 * @retval ptr to new flow object
 * @retval NULL on error
 */
struct pp_flow* pp_flow_construct(struct pp_packet_context *pkt_ctx) {

	struct pp_flow *flow = NULL;
	static uint32_t flow_ids = 0;

	if (!(flow = calloc(1, sizeof(struct pp_flow)))) {
		printf("%s:%d calloc failed\n", __FUNCTION__, __LINE__);
		return NULL;
	}

	flow->id = flow_ids++;
	pthread_mutex_init(&flow->lock, NULL);
	memcpy(flow->protocols, pkt_ctx->protocols, sizeof(pkt_ctx->protocols));

	flow->ep_a.ip.addr.v6 = pkt_ctx->src_addr.v6;
	flow->ep_b.ip.addr.v6 = pkt_ctx->dst_addr.v6;

	flow->ep_a.port = pkt_ctx->src_port;
	flow->ep_b.port = pkt_ctx->dst_port;

	pthread_mutex_init(&flow->lock, NULL);

	__pp_flow_update(flow, pkt_ctx);

	return flow;
}

/**
 * @brief take the packet context and return a flow for it
 * if the flow is allready known, the function just returns the
 * ptr to the existing flow object, if not, a new flow is created
 * and inserted into the flow table
 * @param table to work on
 * @param p_ctx context of the packet to handle
 * @param is_new_flow [out] is set to 1 if a new flow was created
 * @retval ptr to the flow object
 * @retval NULL on error
 */
struct pp_flow* pp_flow_table_get_flow(struct pp_flow_table *table,
									   struct pp_packet_context *pkt_ctx,
									   uint32_t *is_new_flow) {

	uint32_t f_addr = 0;
	int err = 0;
	int bucket = 0;
	struct pp_flow *cur_flow = NULL;

	f_addr = __pp_flow_fold_addresses(pkt_ctx, &err);

	if (unlikely(err)) {
		return NULL;
	}

	bucket = table->hash_fnct(f_addr) % table->size;

	if (table->buckets[bucket]) {

		cur_flow = table->buckets[bucket];
		do {
			if (0 == __pp_flow_table_compare(cur_flow, pkt_ctx)) {
				/* flow allready known */
				__pp_flow_update(cur_flow, pkt_ctx);
				*is_new_flow = 0;
				return cur_flow;
			}

			cur_flow = cur_flow->next_flow;
		} while (cur_flow); /* __loop_flows_in_bucket */

		/* add as new first element */
		cur_flow = table->buckets[bucket];
		*is_new_flow = 1;
		if (!(table->buckets[bucket] = pp_flow_construct(pkt_ctx))) {
			table->buckets[bucket] = cur_flow;
			return NULL;
		}
		table->buckets[bucket]->next_flow = cur_flow;
		return table->buckets[bucket];
	}

	/* add a new flow to the table */
	*is_new_flow = 1;
	return (table->buckets[bucket] = pp_flow_construct(pkt_ctx));
}

/**
 * @brief free flow context
 * @param flow_ctx the flow to be freed
 */
void pp_flow_destroy(struct pp_flow *flow_ctx) {

	assert(flow_ctx->analyzer_data == NULL);
	free(flow_ctx);
}

/**
 * @brief free all elements in the table
 * @param table to be freed
 */
void pp_flow_table_delete(struct pp_flow_table *table) {

	int b = 0;
	struct pp_flow *cur_flow, *next_flow;

	for (b = 0; b < table->size; b++) {
		if (table->buckets[b] != NULL) {
			cur_flow = table->buckets[b];
			do {
				next_flow = cur_flow->next_flow;
				if (table->flow_delete_fntc) {
					table->flow_delete_fntc(cur_flow);
				} else {
					pp_flow_destroy(cur_flow);
				}
				cur_flow = next_flow;
			} while (cur_flow);
		}
	}
	free(table->buckets);
	free(table);
}

/**
 * @brief use packet context to create a unit32_t value that can be used in a hash function
 * @note the functions folds and combines the src/dst ip/port attributes to an uint32_t
 * @param p_ctx context of the packet to handle
 * @param err [out] is set to 1 on error, else 0
 * @retval key
 */
inline uint32_t __pp_flow_fold_addresses(struct pp_packet_context *pkt_ctx, int *err) {

	uint32_t key = 0;
	uint32_t tmp = 0;

	*err = 0;
	switch(pkt_ctx->protocols[PP_OSI_LAYER_3]) {
		case ETH_P_IP:
			/* just xor the ip addresses and the src/dst ports in a
			 * twisted way so we get the same key for both directions
			 * of a flow
			 */
			key = pkt_ctx->src_addr.v4.s_addr ^ pkt_ctx->dst_addr.v4.s_addr;
			tmp = pkt_ctx->src_port ^ pkt_ctx->dst_port;
#if __BYTE_ORDER == __LITTLE_ENDIAN
			tmp |= (tmp << 16);
#elif __BYTE_ORDER == __BIG_ENDIAN
			tmp |= (tmp >> 16);
#else
#error "unknown byte order - are u using a quantum computer?"
#endif
			return (key ^= tmp);
			break;
		case ETH_P_IPV6:
			/* xor 32-bit tupels of the address, use the same twisted
			 * xor for the ports
			 */
			key = pkt_ctx->src_addr.v6.s6_addr32[0] ^ pkt_ctx->dst_addr.v6.s6_addr32[0];
			key ^= pkt_ctx->src_addr.v6.s6_addr32[1] ^ pkt_ctx->dst_addr.v6.s6_addr32[1];
			key ^= pkt_ctx->src_addr.v6.s6_addr32[2] ^ pkt_ctx->dst_addr.v6.s6_addr32[2];
			key ^= pkt_ctx->src_addr.v6.s6_addr32[3] ^ pkt_ctx->dst_addr.v6.s6_addr32[3];
			tmp = pkt_ctx->src_port ^ pkt_ctx->dst_port;
#if __BYTE_ORDER == __LITTLE_ENDIAN
			tmp |= (tmp << 16);
#elif __BYTE_ORDER == __BIG_ENDIAN
			tmp |= (tmp >> 16);
#endif
			return (key ^= tmp);
			break;
		default:
			*err = 1;
	}

	return 0;
}

/**
 * @brief dump flow data
 * @param flow to dump
 */
void pp_flow_dump(struct pp_flow *flow) {

	char ipsrc[INET6_ADDRSTRLEN];
	char ipdst[INET6_ADDRSTRLEN];
	char name_buf[32];

	if (flow->protocols[PP_OSI_LAYER_3] == ETH_P_IP) {
		inet_ntop(AF_INET, &(flow->ep_a.ip.addr.v6), ipsrc, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET, &(flow->ep_b.ip.addr.v6), ipdst, INET6_ADDRSTRLEN);
	} else {
		inet_ntop(AF_INET6, &(flow->ep_a.ip.addr.v6), ipsrc, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(flow->ep_b.ip.addr.v6), ipdst, INET6_ADDRSTRLEN);
	}

	pthread_mutex_lock(&flow->lock);

	printf("-----------------------------------------------\n");
	pp_get_proto_name(PP_OSI_LAYER_3, flow->protocols[PP_OSI_LAYER_3], name_buf, 31);
	printf("%s  %s:%d --> %s:%d\n", name_buf,
									ipsrc, flow->ep_a.port,
									ipdst, flow->ep_b.port);
	pp_get_proto_name(PP_OSI_LAYER_4, flow->protocols[PP_OSI_LAYER_4], name_buf, 31);
	printf("l4-proto:           %s\n", name_buf);
	printf("packets upstream:   %" PRIu64 "\n", flow->data_upstream.packets);
	printf("bytes upstream:     %" PRIu64 "\n", flow->data_upstream.bytes);
	printf("packets downstream: %" PRIu64 "\n", flow->data_downstream.packets);
	printf("bytes downstream:   %" PRIu64 "\n", flow->data_downstream.bytes);
	printf("packets cum:        %" PRIu64 "\n", flow->data_cum.packets);
	printf("bytes cum:          %" PRIu64 "\n", flow->data_cum.bytes);

	pthread_mutex_unlock(&flow->lock);
}

/**
 * @brief dump flows contained in the given flow table
 * @param table to dump
 */
void pp_flow_table_dump(struct pp_flow_table *table) {

	/* TODO: locking is currently only applied on flow level
	 * check if the table must also be protected
	 */
	int b = 0;
	struct pp_flow *cur_flow;

	for (b = 0; b < table->size; b++) {
		if (table->buckets[b] != NULL) {
			cur_flow = table->buckets[b];
			do {
				pp_flow_dump(cur_flow);
				cur_flow = cur_flow->next_flow;
			} while (cur_flow);
		}
	}
}

/**
 * @brief dump flows table stats
 * @param table to show the stats for
 */
void pp_flow_table_stats(struct pp_flow_table *table) {

	/* TODO: apply locking */
	int b = 0;
	struct pp_flow *cur_flow, *next_flow;

	/* buckets of the table in use */
	uint32_t buckets_used = 0;
	/* maximum chain size per bucket */
	uint32_t bucket_global_max_size = 0;
	/* minimum chain size > 0 per bucket */
	uint32_t bucket_global_min_size = UINT32_MAX;
	/* chain size of current bucket */
	uint32_t bucket_local_size = 0;
	/* number of elements in all buckets */
	uint32_t global_size = 0;

	for (b = 0; b < table->size; b++) {
		if (table->buckets[b] != NULL) {
			buckets_used++;
			cur_flow = table->buckets[b];
			bucket_local_size = 0;

			do {
				bucket_local_size++;
				cur_flow = cur_flow->next_flow;
			} while (cur_flow);

			bucket_global_max_size = bucket_local_size>bucket_global_max_size?bucket_local_size:bucket_global_max_size;
			if (bucket_local_size < bucket_global_min_size && bucket_local_size >= 1) {
				bucket_global_min_size = bucket_local_size;
			}
			global_size += bucket_local_size;
		}
	}
	printf("----------------------------------------------\n");
	if (buckets_used) {
		printf("buckets used:     %u\n", buckets_used);
		printf("alpha:            %f\n", (double)global_size/table->size);
		printf("avg bucket size:  %f\n", (double)global_size/buckets_used);
		printf("min bucket size:  %u\n", bucket_global_min_size);
		printf("max bucket size:  %u\n", bucket_global_max_size);
	} else {
		printf("no flow captured\n");
	}
}

