#include "pp_analyse.h"

struct packet analyse(uint8_t *data, uint64_t timestamp) {
	struct packet packet;
	packet.version = 0; // invalid packet
	packet.timestamp = timestamp;
	
	eptr = (struct ether_header *) data; /* ethernet pointer */
	
	// if packet is IP packet
	if (ntohs (eptr->ether_type) == ETHERTYPE_IP) { // IPv4
		/* get mac addresses */
		packet.src_host = eptr->ether_dhost;
		packet.dst_host = eptr->ether_shost;
		
		/* get ip header */
		ip = (struct header_ipv4*)(data + sizeof(struct ether_header));
		packet.version = IP_V(ip);
		
		if (packet.version == 4) { // check for IPv4 header
			packet.length = ip->ip_len;
			packet.protocol = ip->ip_p;
			packet.ip_src = ip->ip_src;
			packet.ip_dst = ip->ip_dst;
		}
	} else if (ntohs (eptr->ether_type) == ETHERTYPE_IPV6) { // IPv6
		/* get mac addresses */
		packet.src_host = eptr->ether_dhost;
		packet.dst_host = eptr->ether_shost;
		
		/* get ip header */
		ipv6 = (struct header_ipv6*)(data + sizeof(struct ether_header));
		packet.version = IP_V(ipv6);
		
		if (packet.version == 6) { // check for IPv6 header
			packet.length = ipv6->ip_pll;
			packet.protocol = ipv6->ip_nxthdr; // TODO extension header not supported
			packet.ip6_src = ipv6->ip_src;
			packet.ip6_dst = ipv6->ip_dst;
		}
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
		inet_ntop(AF_INET, &(packet->ip_src), ipsrc, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &(packet->ip_dst), ipdst, INET_ADDRSTRLEN);
	} else {
		inet_ntop(AF_INET6, &(packet->ip6_src), ipsrc, INET6_ADDRSTRLEN);
		inet_ntop(AF_INET6, &(packet->ip6_dst), ipdst, INET6_ADDRSTRLEN);
	}
	printf("\t[%s:%u] --> [%s:%u] ", ipsrc, 0, ipdst, 0);
	printf("\tsize: %u B", packet->length);
	printf("\ttime: %" PRIu64 "\n", packet->timestamp);
}