#include "pp_decap.h"

static int __pp_decap_l2(uint32_t protocol, size_t *len, uint32_t *offset, struct pp_packet_context *pkt_ctx);
static int __pp_decap_l23(uint32_t protocol, size_t *len, uint32_t *offset, struct pp_packet_context *pkt_ctx);
static int __pp_decap_l3(uint32_t protocol, size_t *len, uint32_t *offset, struct pp_packet_context *pkt_ctx);
static int __pp_decap_l4(uint32_t protocol, size_t *len, uint32_t *offset, struct pp_packet_context *pkt_ctx);
static int __pp_decap_ipv6_options(uint32_t protocol, size_t *len, uint32_t *offset, struct pp_packet_context *pkt_ctx);

/**
 * @brief general packet decapsulation
 * @param first_layer where to start in the osi layer to parse the packet
 * @param data of the packet
 * @param len of the packet in bytes
 * @param timestamp the packet was received (usec)
 * @param pkt_ctx holds the context of the current packet
 * @param filter points to the berkley packet filter program (NULL if not used)
 * @retval PP_DECAP_OKAY on success
 * @retval !=PP_DECAP_OKAY
 */
enum PP_DECAP_RESULT pp_decap(enum PP_OSI_LAYERS first_layer,
							  uint8_t *data,
							  size_t len,
							  uint64_t ts_usec,
							  struct pp_packet_context *pkt_ctx,
							  struct bpf_insn *filter) {

	int32_t rc_proto = 0;
	uint32_t offset = 0;

	assert(pkt_ctx);

	pkt_ctx->packet = data;
	pkt_ctx->length = len;
	pkt_ctx->timestamp = ts_usec;
	memset(pkt_ctx->protocols, 0, sizeof(pkt_ctx->protocols));
	memset(pkt_ctx->offsets, 0, sizeof(pkt_ctx->offsets));
	memset(&pkt_ctx->src_addr.v6, 0, sizeof(pkt_ctx->src_addr.v6));
	memset(&pkt_ctx->dst_addr.v6, 0, sizeof(pkt_ctx->src_addr.v6));
	pkt_ctx->direction = PP_PKT_DIR_UNKNOWN;

	if (likely(first_layer == PP_OSI_LAYER_2)) {
		if ((rc_proto = __pp_decap_l2(0, &len, &offset, pkt_ctx)) >= 0 ) {
			if ((rc_proto = __pp_decap_l3(rc_proto, &len, &offset, pkt_ctx)) >= 0) {
				return __pp_decap_l4(rc_proto, &len, &offset, pkt_ctx);
			}
		}
	} else if (first_layer == PP_OSI_LAYER_3) {

		/* get version from packet - malicious packets could kill us */
		rc_proto = ((struct iphdr*)data)->version == 4 ? ETH_P_IP : ETH_P_IPV6;
		if ((rc_proto = __pp_decap_l3(rc_proto, &len, &offset, pkt_ctx)) >= 0) {
			return __pp_decap_l4(rc_proto, &len, &offset, pkt_ctx);
		}
	} else {
		return -PP_DECAP_INVALID_FIRST_LAYER;
	}

	return rc_proto;
}

/**
 * @brief decapsulate layer 2
 * @note currently we only deal with ll type ethernet
 * @param protocol used on the layer
 * @param data of the packet
 * @param len of the date in bytes
 * @param pkt_ctx that holds the informations of the packet
 * @retval >=0 layer 2/3 | 3 protocol
 * @retval -PP_DECAP_L2_* on error
 */
static int __pp_decap_l2(uint32_t protocol, size_t *len, uint32_t *offset, struct pp_packet_context *pkt_ctx) {

	if (*len < ETH_HLEN) {
		return -PP_DECAP_L2_ERROR;
	}

	pkt_ctx->protocols[PP_OSI_LAYER_2] = 0;
	pkt_ctx->offsets[PP_OSI_LAYER_2] = *offset;

	*len -= ETH_HLEN;
	*offset += ETH_HLEN;

	return ntohs(((struct ether_header*) pkt_ctx->packet)->ether_type);
}

/**
 * @brief decapsulate layer 2/3 (802-q)
 * @param protocol used on the layer
 * @param data of the packet
 * @param len of the date in bytes
 * @param pkt_ctx that holds the informations of the packet
 * @retval >=0 layer 3 protocol
 * @retval -PP_DECAP_L2_* on error
 */
static int __pp_decap_l23(uint32_t protocol, size_t *len, uint32_t *offset, struct pp_packet_context *pkt_ctx) {

	int next_proto = 0;

	if (*len < 2) {
		return -PP_DECAP_L2_ERROR;
	}

	next_proto = ntohs((uint16_t)pkt_ctx->packet[*offset + 4]);

	*len -= 4;
	*offset += 4;

	return next_proto;
}

/**
 * @brief decapsulate layer 3
 * @param protocol used on the layer
 * @param data of the packet
 * @param len of the date in bytes
 * @param pkt_ctx that holds the informations of the packet
 * @retval >=0 layer 4 protocol
 * @retval -PP_DECAP_L3_* on error
 */
static int __pp_decap_l3(uint32_t protocol, size_t *len, uint32_t *offset, struct pp_packet_context *pkt_ctx) {

	struct iphdr* ip_hdr = NULL;
	struct ip6_hdr* ipv6_hdr = NULL;

	switch (protocol) {
	case ETH_P_8021Q:
		return __pp_decap_l3(__pp_decap_l23(protocol, len, offset, pkt_ctx), len, offset, pkt_ctx);

	case ETH_P_IP:
		if (*len < sizeof(struct iphdr)) {
			return -PP_DECAP_L3_ERROR;
		}
		ip_hdr = (struct iphdr*)(&pkt_ctx->packet[*offset]);

		if (unlikely(ip_hdr->version != 4)) {
			return -PP_DECAP_L3_ERROR;
		}

		pkt_ctx->protocols[PP_OSI_LAYER_3] = ETH_P_IP;
		pkt_ctx->offsets[PP_OSI_LAYER_3] = *offset;
		pkt_ctx->l3_meta.ip.length = htons(ip_hdr->tot_len);
		pkt_ctx->src_addr.v4.s_addr = ip_hdr->saddr;
		pkt_ctx->dst_addr.v4.s_addr = ip_hdr->daddr;

		*len -= ip_hdr->ihl*4;
		*offset += ip_hdr->ihl*4;

		/* fall through if packet is IPv6-in-IPv4 */
		if (ip_hdr->protocol != IPPROTO_IPV6) {
			return ip_hdr->protocol;
		}

	case ETH_P_IPV6:
		if (*len < sizeof(struct ip6_hdr)) {
			return -PP_DECAP_L3_ERROR;
		}
		ipv6_hdr = (struct ip6_hdr*)(&pkt_ctx->packet[*offset]);

		if (unlikely(((ipv6_hdr->ip6_vfc & 0xf0) >> 4) != 6)) {
			return -PP_DECAP_L3_ERROR;
		}
		pkt_ctx->protocols[PP_OSI_LAYER_3] = ETH_P_IPV6;
		pkt_ctx->offsets[PP_OSI_LAYER_3] = *offset;

		pkt_ctx->l3_meta.ipv6.length = htons(ipv6_hdr->ip6_plen);
		pkt_ctx->src_addr.v6 = ipv6_hdr->ip6_src;
		pkt_ctx->dst_addr.v6 = ipv6_hdr->ip6_dst;

		*len -= sizeof(struct ip6_hdr);
		*offset += sizeof(struct ip6_hdr);

		return __pp_decap_ipv6_options(ipv6_hdr->ip6_nxt, len, offset, pkt_ctx);
	default:
		return -PP_DECAP_L3_PROTO_UNKNOWN;
	}
}

/**
 * @brief decapsulate ipv6 option headers
 * @param protocol used for the actual header
 * @param data of the packet
 * @param len of the date in bytes
 * @param pkt_ctx that holds the informations of the packet
 * @retval protocol type of the next layer on success
 * @retval -PP_DECAP_L3_* on error
 */
static int __pp_decap_ipv6_options(uint32_t protocol, size_t *len, uint32_t *offset, struct pp_packet_context *pkt_ctx) {

	switch(protocol) {
		case IPPROTO_TCP:
		case IPPROTO_UDP:
			return protocol;
		case IPPROTO_HOPOPTS:
		case IPPROTO_DSTOPTS:
		case IPPROTO_ROUTING:
			if (*len < sizeof(struct ip6_ext)) {
				return -PP_DECAP_L3_ERROR;
			}
			struct ip6_ext *ext_hdr = (struct ip6_ext*)&pkt_ctx->packet[*offset];

			*len -= (ext_hdr->ip6e_len + 1) * 8;
			*offset += (ext_hdr->ip6e_len +1) * 8;
			return __pp_decap_ipv6_options(ext_hdr->ip6e_nxt, len, offset, pkt_ctx);
		case IPPROTO_FRAGMENT:
			if (*len < sizeof(struct ip6_frag)) {
				return -PP_DECAP_L3_ERROR;
			}
			struct ip6_frag *frag_hdr = (struct ip6_frag*)&pkt_ctx->packet[*offset];

			*len -= sizeof(struct ip6_frag);
			*offset += sizeof(struct ip6_frag);
			return __pp_decap_ipv6_options(frag_hdr->ip6f_nxt, len, offset, pkt_ctx);
		case IPPROTO_ICMPV6:
		case IPPROTO_NONE: /* no next header */
		default:
			return -PP_DECAP_L3_PROTO_UNKNOWN;
	}
}

/**
 * @brief decapsulate layer 4
 * @param protocol used on the layer
 * @param data of the packet
 * @param len of the date in bytes
 * @param pkt_ctx that holds the informations of the packet
 * @retval PP_DECAP_OKAY on success
 * @retval -PP_DECAP_L4_* on error
 */
static int __pp_decap_l4(uint32_t protocol, size_t *len, uint32_t *offset, struct pp_packet_context *pkt_ctx) {

	struct tcphdr* tcp_hdr = NULL;
	struct udphdr* udp_hdr = NULL;

	switch(protocol) {
	case IPPROTO_TCP:
		if (*len < sizeof(struct tcphdr)) {
			return -PP_DECAP_L4_ERROR;
		}
		tcp_hdr = (struct tcphdr*)&pkt_ctx->packet[*offset];

		pkt_ctx->protocols[PP_OSI_LAYER_4] = IPPROTO_TCP;
		pkt_ctx->offsets[PP_OSI_LAYER_4] = *offset;
		pkt_ctx->l4_meta.tcp.window_size = htons(tcp_hdr->window);
		pkt_ctx->l4_meta.tcp.fin = tcp_hdr->fin;
		pkt_ctx->l4_meta.tcp.syn = tcp_hdr->syn;
		pkt_ctx->l4_meta.tcp.rst = tcp_hdr->rst;
		pkt_ctx->l4_meta.tcp.ack = tcp_hdr->ack;
	        pkt_ctx->l4_meta.tcp.ack_num = htonl(tcp_hdr->ack_seq);
	        pkt_ctx->l4_meta.tcp.seq_num = htonl(tcp_hdr->seq);
	        pkt_ctx->l4_meta.tcp.hl      = tcp_hdr->doff*4;
		pkt_ctx->src_port = htons(tcp_hdr->source);
		pkt_ctx->dst_port = htons(tcp_hdr->dest);

		*len -= tcp_hdr->doff * 4;
		*offset += tcp_hdr->doff * 4;
		return PP_DECAP_OKAY;
	case IPPROTO_UDP:
		if (*len < sizeof(struct udphdr)) {
			return -PP_DECAP_L4_ERROR;
		}
		udp_hdr = (struct udphdr*)&pkt_ctx->packet[*offset];

		pkt_ctx->protocols[PP_OSI_LAYER_4] = IPPROTO_UDP;
		pkt_ctx->offsets[PP_OSI_LAYER_4] = *offset;
		pkt_ctx->src_port = htons(udp_hdr->source);
		pkt_ctx->dst_port = htons(udp_hdr->dest);

		*len -= sizeof(struct udphdr);
		*offset += sizeof(struct udphdr);
		return PP_DECAP_OKAY;
	default:
		return -PP_DECAP_L4_PROTO_UNKNOWN;
	}
}

void pp_dump_packet(struct pp_packet_context* pkt_ctx) {

	char ipsrc[INET6_ADDRSTRLEN];
	char ipdst[INET6_ADDRSTRLEN];

	switch(pkt_ctx->protocols[PP_OSI_LAYER_3]) {
	case ETH_P_IP:
		printf("IPv4 ");
		inet_ntop(AF_INET, &(pkt_ctx->src_addr.v4), ipsrc, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(pkt_ctx->dst_addr.v4), ipdst, INET_ADDRSTRLEN);
		break;
	case ETH_P_IPV6:
		printf("IPv6 ");
		inet_ntop(AF_INET6, &(pkt_ctx->src_addr.v6), ipsrc, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(pkt_ctx->dst_addr.v6), ipdst, INET6_ADDRSTRLEN);
		break;
	default:
		printf("Unsupported packet version on layer 3.\n");
		return;
	}

	switch(pkt_ctx->protocols[PP_OSI_LAYER_4]) {
	case IPPROTO_TCP:
		printf("TCP (%c%c%c%c)", pkt_ctx->l4_meta.tcp.ack?'A':'-',
		                         pkt_ctx->l4_meta.tcp.syn?'S':'-',
		                         pkt_ctx->l4_meta.tcp.rst?'R':'-',
		                         pkt_ctx->l4_meta.tcp.fin?'F':'-');
		break;
	case IPPROTO_UDP:
		printf("UDP ");
		break;
	default:
		printf("Unsupported packet version on layer 4.\n");
		return;
	}

	printf("\t[%s:%u] --> [%s:%u] ", ipsrc, pkt_ctx->src_port, ipdst, pkt_ctx->dst_port);
	printf("\tsize: %u B", pkt_ctx->length);
	printf("\ttime: %" PRIu64 "\n", pkt_ctx->timestamp);
}

static struct __pp_direction_string {
	char *str_short;
	char *str_long;
} pp_direction_strings[] = {
	[PP_PKT_DIR_UPSTREAM] = {"up", "upstream"},
	[PP_PKT_DIR_UNKNOWN] = {"??", "unknown"},
	[PP_PKT_DIR_DOWNSTREAM] = {"down", "downstream"},
	[PP_PKT_DIR_EOL] = {"err", "error"}
};

const char* pp_packet_direction2str(enum __pp_packet_direction dir) {

	return pp_direction_strings[dir].str_short;
}

const char* pp_packet_direction2strlong(enum __pp_packet_direction dir) {
	return pp_direction_strings[dir].str_long;
}
