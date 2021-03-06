#ifndef __PP_FLOW
#define __PP_FLOW

#include <stdint.h>
#include <time.h>
#include <pthread.h>
#include <arpa/inet.h>

#include <pp_decap.h>

struct pp_ip {

	uint8_t version;

	union {
		struct in_addr  v4;
		struct in6_addr v6;
	} addr;
};

struct pp_flow_endpoint {
	struct pp_ip ip;
	uint16_t port;
};

struct pp_flow_data {

	uint64_t bytes;
	uint64_t packets;
};

struct pp_flow {

	/* unique id */
	uint32_t id;

	/* next flow in the same bucket */
	struct pp_flow *next_flow;

	/* pkts / bytes upstream */
	struct pp_flow_data data_upstream;

	/* pkts / bytes downstream */
	struct pp_flow_data data_downstream;

	/* pkts / bytes total */
	struct pp_flow_data data_cum;

	/* source of the first packet seen for the flow
	 * direction src -> dst => upstream
	 */
	struct pp_flow_endpoint ep_a;

	/* dest of the first packet seen for the flow
	 * direction dst -> src => downstream
	 */
	struct pp_flow_endpoint ep_b;

	/* protocol stack */
	uint32_t protocols[PP_OSI_EOL];

	/* first time we got a packet for the flow in usec */
	uint64_t first_seen;

	/* last time we got a packet for the flow in usec */
	uint64_t last_seen;

	/* analyzers per flow data storage */
	void **analyzer_data;

	/* count number of analyzer_data entries (=number of analyzers available)*/
	int analyzer_data_num;

	/* per flow lock */
	pthread_mutex_t lock;

	/* ndpi */
	struct ndpi_flow_struct *ndpi_flow_ctx;
	struct ndpi_id_struct *ndpi_src;
	struct ndpi_id_struct *ndpi_dst;

	uint32_t ndpi_protocol;
	uint8_t ndpi_shortcut;
};

struct pp_flow_table {

	struct pp_flow **buckets;

	/* function to be called on flow delete */
	void (*flow_delete_fntc)(struct pp_flow*);

	/* hash function to be used, defaults to Thomas Wang hash */
	uint32_t (*hash_fnct)(uint32_t key);

	uint32_t size;
};

struct pp_flow_list_entry {

	struct pp_flow *flow;
	struct pp_flow_list_entry *next;
	struct pp_flow_list_entry *prev;
};

struct pp_flow_list {

	struct pp_flow_list_entry *head;
	struct pp_flow_list_entry *tail;
};


uint32_t __pp_flow_fold_addresses(struct pp_packet_context *pkt_ctx, int *err);
struct pp_flow_table* pp_flow_table_create(uint32_t size,
										   void (*flow_delete_fntc)(struct pp_flow*),
										   uint32_t (*hash_fnct)(uint32_t key));

void pp_flow_table_delete(struct pp_flow_table *table);
void pp_flow_destroy(struct pp_flow *flow_ctx);

struct pp_flow* pp_flow_construct(struct pp_packet_context *pkt_ctx);

struct pp_flow* pp_flow_table_get_flow(struct pp_flow_table *table,
									   struct pp_packet_context *pkt_ctx,
									   uint32_t *is_new_flow);

void pp_flow_dump(struct pp_flow *flow);
void pp_flow_table_dump(struct pp_flow_table *table);
void pp_flow_table_stats(struct pp_flow_table *table);

#endif /* __PP_FLOW */
