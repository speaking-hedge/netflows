#ifndef __PP_ANALYSE_H
#define __PP_ANALYSE_H

#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <stdio.h>
#include <inttypes.h>

struct packet {
	u_int64_t       timestamp;      /* timestamp */
	char            *src_host;       /* mac address of source, len = ETHER_ADDR_LEN */
	char            *dst_host;       /* mac address of destination*/
	u_int8_t        version;         /* protocol version          */
	u_int16_t       length;          /* packet length             */
	u_int8_t        protocol;        /* package protocol          */
	struct in_addr  ip_src,
	                ip_dst;          /* source and dest address   */
	struct in6_addr ip6_src,
	                ip6_dst;         /* ip adresses               */
};

struct header_ipv6 {
	u_int32_t       ip_vhl;          /* version, traffic class, flow label */
	u_int16_t       ip_pll;          /* payload length            */
	u_int8_t        ip_nxthdr;       /* next header               */
	u_int8_t        ip_ttl;          /* hop limit aka ttl         */
	struct in6_addr ip_src, ip_dst;  /* ip adresses               */
};

struct header_ipv4 {
	u_int8_t        ip_vhl;          /* header length, version    */
#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)   ((ip)->ip_vhl & 0x0f)
	u_int8_t        ip_tos;          /* type of service           */
	u_int16_t       ip_len;          /* total length              */
	u_int16_t       ip_id;           /* identification            */
	u_int16_t       ip_off;          /* fragment offset field     */
#define IP_DF 0x4000                 /* dont fragment flag        */
#define IP_MF 0x2000                 /* more fragments flag       */
#define IP_OFFMASK 0x1fff            /* mask for fragmenting bits */
	u_int8_t        ip_ttl;          /* time to live              */
	u_int8_t        ip_p;            /* protocol                  */
	u_int16_t       ip_sum;          /* checksum                  */
	struct  in_addr ip_src, ip_dst;  /* source and dest address   */
};

struct ether_header *eptr;
int i;
u_char *ptr;

const struct header_ipv4* ip;
const struct header_ipv6* ipv6;
char ipsrc[INET6_ADDRSTRLEN];
char ipdst[INET6_ADDRSTRLEN];

struct packet analyse(uint8_t *data, uint64_t timestamp);

#endif
