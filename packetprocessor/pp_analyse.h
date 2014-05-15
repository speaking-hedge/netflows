#ifndef __PP_ANALYSE_H
#define __PP_ANALYSE_H

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdio.h>
#include <inttypes.h>

/*
 * Structs
 */

/* packet information */
struct packet {
	u_int64_t       timestamp; // time stamp
	u_int8_t        version;   // version
	u_int16_t       length;    // packet size
	u_int8_t        protocol;  // protocol

	struct in_addr  src_ip,    // source ip address
	                dst_ip;    // destination ip address
	struct in6_addr src_ip6,   // source ipv6 address // TODO: check if in6_addr can hold ipv4 addresses
	                dst_ip6;   // destination ipv6 address
	in_port_t       src_port,  // source port
	                dst_port;  // destination port
};

/* TCP Header */
struct header_tcp {
	in_port_t src_port;        // source port // short because of byte order
	in_port_t dst_port;        // destination port
	u_int32_t seq_nr;          // sequence number
	u_int32_t ack_nr;          // acknowledge number
	u_int16_t flags;           // data offset / control flags
	u_int16_t window;          // receive window size
	u_int16_t checksum;        // checksum
	u_int16_t urgent;          // urgent pointer
};

/* IPv6 header */
struct header_ipv6 {
	u_int32_t       version;   // version, traffic class, flow label
	u_int16_t       payload;   // payload length
	u_int8_t        nexthdr;   // next header
	u_int8_t        ttl;       // time to live
	struct in6_addr src_ip,    // source ip address
	                dst_ip;    // destination ip address
};

/* IPv4 header */
struct header_ipv4 {
	u_int8_t        version;   // version / header length
	u_int8_t        tos;       // type of service
	u_int16_t       length;    // total length
	u_int16_t       id;        // identification
	u_int16_t       offset;    // flags / offset
	u_int8_t        ttl;       // time to live
	u_int8_t        protocol;  // protocol
	u_int16_t       checksum;  // checksum
	struct  in_addr src_ip,    // source ip address
	                dst_ip;    // destination ip address
};

/*
 * variables
 */
struct ether_header *eptr;
const struct header_ipv4* ip;
const struct header_ipv6* ipv6;
const struct header_tcp* tcp;

char ipsrc[INET6_ADDRSTRLEN]; // ip address string reserved
char ipdst[INET6_ADDRSTRLEN]; // ip address string reserved

/* 
 * functions
 */
struct packet analyse(uint8_t *data, uint64_t timestamp);
void print_packet_info(struct packet* packet);

#endif
