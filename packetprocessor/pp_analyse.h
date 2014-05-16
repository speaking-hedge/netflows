#ifndef __PP_ANALYSE_H
#define __PP_ANALYSE_H

/**
 * layer / supported protocols
 * ------------------------------
 * 2 Ethernet, 802-1.Q
 * ------------------------------
 * 3 IP, IPv6
 * ------------------------------
 * 4 TCP, UDP
 */

/* dude, see /usr/include/netinet/ */
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <stdio.h>
#include <inttypes.h>
#include <string.h>
#include <assert.h>

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

/* packet information */
struct packet_context {

	/* point to the packet data */
	uint8_t *packet;

	/* time we got the packet */
	uint64_t timestamp;

	/* size in bytes l2..l7*/
	uint16_t length;

	/* offset of each layer to the packet start */
	uint32_t offsets[PP_OSI_EOL];

	/* protocol detected on each layer */
	uint32_t protocols[PP_OSI_EOL];

	/******* network layer *******/

	/* src/dst ip/ipv6 addresses */
	union {
		struct in_addr  v4;
		struct in6_addr v6;
	} src_addr;
	union {
		struct in_addr  v4;
		struct in6_addr v6;
	} dst_addr;

	/******* transport layer *******/

	/* protocol specific meta informations */
	union {
		struct {
			uint16_t window_size;
			uint16_t fin:1;
			uint16_t syn:1;
			uint16_t rst:1;
			uint16_t ack:1;
		} tcp;
	} l4_meta;

	/* src/dst ports */
	in_port_t       src_port;
	in_port_t       dst_port;
};

#ifdef __GNUC__
#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)
#else
#define likely(x)       (x)
#define unlikely(x)     (x)
#endif

int pp_decap(uint8_t *data, size_t len, uint64_t ts, struct packet_context *pkt_ctx);
void pp_dump_packet(struct packet_context *pkt_ctx);

#endif
