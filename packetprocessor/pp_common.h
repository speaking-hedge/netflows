#ifndef __PP_COMMON_H
#define __PP_COMMON_H

#define _GNU_SOURCE

#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <pcap/bpf.h>
#include <ethertype.h>

/* number of buckets inside the hash table */
#define PP_FLOW_HASH_TABLE_BUCKETS	4099

enum PP_DECAP_RESULT {
	/* packet successfull decapsulated and analysed */
	PP_DECAP_OKAY = 0,
	/* l2 error during packet decapsulation */
	PP_DECAP_L2_ERROR,
	/* l3 error during packet decapsulation */
	PP_DECAP_L3_ERROR,
	/* l4 error during packet decapsulation */
	PP_DECAP_L4_ERROR,
	/* l2 - protocol not supported */
	PP_DECAP_L2_PROTO_UNKNOWN,
	/* l3 - protocol not supported */
	PP_DECAP_L3_PROTO_UNKNOWN,
	/* l4 - protocol not supported */
	PP_DECAP_L4_PROTO_UNKNOWN,
	PP_DECPA_EOL
};

enum PP_OSI_LAYERS {
	PP_OSI_LAYER_1 = 0,
	PP_OSI_LAYER_2,
	PP_OSI_LAYER_3,
	PP_OSI_LAYER_4,
	PP_OSI_LAYER_5,
	PP_OSI_LAYER_6,
	PP_OSI_LAYER_7,
	PP_OSI_EOL
};

enum pp_flowtop_sort_criteria {
	PP_FT_SORT_BY_NONE = 0,
	PP_FT_SORT_BY_ID,
	PP_FT_SORT_BY_L3,
	PP_FT_SORT_BY_L4,
	PP_FT_SORT_BY_L57,
	PP_FT_SORT_BY_SRC_ADDR,
	PP_FT_SORT_BY_DST_ADDR,
	PP_FT_SORT_BY_SRC_PORT,
	PP_FT_SORT_BY_DST_PORT,
	PP_FT_SORT_BY_PKT_UP,
	PP_FT_SORT_BY_PKT_DOWN,
	PP_FT_SORT_BY_BYT_UP,
	PP_FT_SORT_BY_BYT_DOWN,
	PP_FT_SORT_BY_AGE,
	PP_FT_SORT_BY_LAST_SEEN,
	PP_FT_SORT_BY_EOL
};

enum pp_flowtop_sort_order {
	PP_FT_SORT_ORDER_ASCENDING = 0,
	PP_FT_SORT_ORDER_DESCENDING,
	PP_FT_SORT_ORDER_EOL
};

#endif /* __PP_COMMON_H */
