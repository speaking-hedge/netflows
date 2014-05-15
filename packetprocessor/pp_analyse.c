#include "pp_analyse.h"

/**
 * @brief general packet analyse
 * @param data of the packet
 * @param timestamp the packet was received
 */
struct packet analyse(uint8_t *data, uint64_t timestamp) {
	struct packet packet; // return value

	packet.version = 0; // invalid packet
	packet.timestamp = timestamp;
	
	/* get ethernet header */
	eptr = (struct ether_header *) data;
	
	// if packet is IP packet
	if (ntohs (eptr->ether_type) == ETHERTYPE_IP) { // IPv4
		/* get ip header */
		ip = (struct header_ipv4*)(data + sizeof(struct ether_header));

		packet.version = (ip->version & 0xf0) >> 4;

		if (packet.version == 4) { // check for IPv4 header
			packet.length = htons(ip->length);
			packet.protocol = ip->protocol;
			packet.src_ip = ip->src_ip;
			packet.dst_ip = ip->dst_ip;
		}

		/* get tcp header */
		tcp = (struct header_tcp*)(data + sizeof(struct ether_header) + (ip->version & 0x0f)*4); 

		packet.src_port = htons(tcp->src_port);
		packet.dst_port = htons(tcp->dst_port);

	} else if (ntohs (eptr->ether_type) == ETHERTYPE_IPV6) { // IPv6
		/* get ip header */
		ipv6 = (struct header_ipv6*)(data + sizeof(struct ether_header));

		packet.version = (ipv6->version & 0xf0) >> 4;

		if (packet.version == 6) { // check for IPv6 header
			packet.length = htons(ipv6->payload);
			packet.protocol = ipv6->nexthdr; // TODO extension header not supported
			packet.src_ip6 = ipv6->src_ip;
			packet.dst_ip6 = ipv6->dst_ip;
		}

		/* get tcp header */
		tcp = (struct header_tcp*)(data + sizeof(struct ether_header) + sizeof(struct header_ipv6)); 

		packet.src_port = htons(tcp->src_port);
		packet.dst_port = htons(tcp->dst_port);
	}

	return packet;
}

void print_packet_info(struct packet* packet) {
	if (packet->version == 4) {
		printf("IPv4 ");
	} else if (packet->version == 6) {
		printf("IPv6 ");
	} else {
		printf("Unsupported packet version.\n");
		return;
	}
	
	if (packet->protocol = IPPROTO_TCP) {
		printf("TCP ");
	} else if (packet->protocol = IPPROTO_UDP) {
		printf("UDP ");
	}

	if (packet->version == 4) {
		inet_ntop(AF_INET, &(packet->src_ip), ipsrc, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(packet->dst_ip), ipdst, INET_ADDRSTRLEN);
	} else {
		inet_ntop(AF_INET6, &(packet->src_ip6), ipsrc, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(packet->dst_ip6), ipdst, INET6_ADDRSTRLEN);
	}
	printf("\t[%s:%u] --> [%s:%u] ", ipsrc, packet->src_port, ipdst, packet->dst_port);
	printf("\tsize: %u B", packet->length);
	printf("\ttime: %" PRIu64 "\n", packet->timestamp);
}