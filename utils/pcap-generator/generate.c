#include "generate.h"

/**
 * @brief write the header of the pcap file
 * @param *file file to write to
 */
void write_pcap_header(FILE *file)
{
	struct pcap_hdr_s pcap_header;
	pcap_header.magic_number = 0xa1b2c3d4;
	pcap_header.version_major = 2;
	pcap_header.version_minor = 4;
	pcap_header.thiszone = 0;
	pcap_header.sigfigs = 0;
	pcap_header.snaplen = 0xffff;
	pcap_header.network = 1; // 1 = ethernet

	fwrite(&pcap_header, sizeof(struct pcap_hdr_s), 1, file);
}

/**
 * @brief write the header of a packet (1)
 * @param *file file to write to
 * @param len length of the packeckts data
 * @param timeadd microseconds to add
 */
void write_packet_header(FILE *file, size_t len, unsigned int timeadd)
{
	static unsigned int dtime = 0;
	dtime += timeadd;
	
	struct tm time; // date doen't matter
	time.tm_sec = (dtime/1000000);
	time.tm_min = 0;
	time.tm_hour = 12;
	time.tm_mday = 1;
	time.tm_mon = 1;
	time.tm_year = 114;
	time_t t = mktime(&time);

	struct pcaprec_hdr_s pac_header;
	pac_header.ts_sec = t;
	pac_header.ts_usec = dtime%1000000;
	pac_header.incl_len = len;
	pac_header.orig_len = len;
	fwrite(&pac_header, sizeof(struct pcaprec_hdr_s), 1, file);
}

/**
 * @brief write the ethernet header (2)
 * @param *file file to write to
 * @param shost source host
 * @param dhost destination host
 */
void write_layer2(FILE *file, struct net_host *shost, struct net_host *dhost)
{
	struct ether_header layer2;
	int a = 0;
	for (a = 0; a < 6; a++)
	{
		layer2.ether_dhost[a] = dhost->ether_host[a];
		layer2.ether_shost[a] = shost->ether_host[a];
	}
	layer2.ether_type = htons(ETH_P_IP);
	fwrite(&layer2, sizeof(struct ether_header), 1, file);
}

/**
 * @brief write the IPv4 header (3)
 * @param *file file to write to
 * @param shost source host
 * @param dhost destination host
 * @param length of the data
 */
void write_layer3_ip4(FILE *file, struct net_host *shost, struct net_host *dhost, size_t len)
{
	struct iphdr layer3;
	layer3.version = 4;
	layer3.ihl = 5;
	layer3.tos = 0x00;
	layer3.tot_len = htons(len);
	layer3.id = 0;
	layer3.frag_off = 0;
	layer3.ttl = 5;
	layer3.protocol = 6; // 6 = tcp
	layer3.check = 0; // wrong checksum
	layer3.saddr = shost->addr; //0x0100007f; // 127.0.0.1
	layer3.daddr = dhost->addr; 

	fwrite(&layer3, sizeof(struct iphdr), 1, file);
}

/**
 * @brief write the tcp header (4)
 * @param *file file to write to
 * @param shost source host
 * @param dhost destination host
 * @param syn syn flag
 * @param ack ack flag
 * @param fin fin flag
 */
void write_layer4_tcp(FILE *file, struct net_host *shost, struct net_host *dhost, __u16 syn, __u16 ack, __u16 fin, __u32 len)
{
	struct tcphdr layer4;
	memset(&layer4, 0, sizeof(struct tcphdr));
	layer4.source = htons(shost->port);
	layer4.dest = htons(dhost->port);
	layer4.doff = 5;
	layer4.window = 1;
	layer4.seq = htonl(shost->seq);
	if (ack)
	{
		layer4.ack_seq = htonl(dhost->seq);
	} else {
		layer4.ack_seq = 0;
	}
	layer4.syn = syn;
	layer4.ack = ack;
	layer4.fin = fin;
	shost->seq += len;
	fwrite(&layer4, sizeof(struct tcphdr), 1, file);
}

/**
 * @brief send a syn packet
 * @param *file file to write to
 * @param shost source host
 * @param dhost destination host
 */
void send_syn(FILE *file, struct net_host *shost, struct net_host *dhost)
{
	write_packet_header(file, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr), 5);
	write_layer2(file, shost, dhost);
	write_layer3_ip4(file, shost, dhost, sizeof(struct iphdr) + sizeof(struct tcphdr));
	write_layer4_tcp(file, shost, dhost, 1, 0, 0, 1);
}

/**
 * @brief send a fin packet
 * @param *file file to write to
 * @param shost source host
 * @param dhost destination host
 */
void send_fin(FILE *file, struct net_host *shost, struct net_host *dhost)
{
	write_packet_header(file, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr), 5);
	write_layer2(file, shost, dhost);
	write_layer3_ip4(file, shost, dhost, sizeof(struct iphdr) + sizeof(struct tcphdr));
	write_layer4_tcp(file, shost, dhost, 0, 0, 1, 1);
}

/**
 * @brief send a syn-ack packet
 * @param *file file to write to
 * @param shost source host
 * @param dhost destination host
 */
void send_syn_ack(FILE *file, struct net_host *shost, struct net_host *dhost)
{
	write_packet_header(file, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr), 5);
	write_layer2(file, shost, dhost);
	write_layer3_ip4(file, shost, dhost, sizeof(struct iphdr) + sizeof(struct tcphdr));
	write_layer4_tcp(file, shost, dhost, 1, 1, 0, 1);
}

/**
 * @brief send an ack packet
 * @param *file file to write to
 * @param shost source host
 * @param dhost destination host
 */
void send_ack(FILE *file, struct net_host *shost, struct net_host *dhost)
{
	write_packet_header(file, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr), 5);
	write_layer2(file, shost, dhost);
	write_layer3_ip4(file, shost, dhost, sizeof(struct iphdr) + sizeof(struct tcphdr));
	write_layer4_tcp(file, shost, dhost, 0, 1, 0, 0);
}

/**
 * @brief simulate a tcp connection between two hosts
 * @param *file file to write to
 * @param shost source host
 * @param dhost destination host
 */
void tcp_connect(FILE *file, struct net_host *shost, struct net_host *dhost)
{
	send_syn(file, shost, dhost);
	send_syn_ack(file, dhost, shost);
	send_ack(file, shost, dhost);
}

/**
 * @brief simulate a tcp connection between two hosts
 * @param *file file to write to
 * @param shost source host
 * @param dhost destination host
 */
void tcp_disconnect(FILE *file, struct net_host *shost, struct net_host *dhost)
{
	send_fin(file, shost, dhost);
	send_ack(file, dhost, shost);
	send_fin(file, dhost, shost);
	send_ack(file, shost, dhost);
}

void send_data(FILE *file, struct net_host *shost, struct net_host *dhost, char *data)
{
	write_packet_header(file, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data), 5);
	write_layer2(file, shost, dhost);
	write_layer3_ip4(file, shost, dhost, sizeof(struct iphdr) + sizeof(struct tcphdr) + strlen(data));
	write_layer4_tcp(file, shost, dhost, 0, 0, 0, strlen(data));
	fwrite(data, strlen(data), 1, file);

	send_ack(file, dhost, shost);
}

/**
 * @brief main class
 * @param file filename to write to
 */
int main(int argc, char **argv) {

	FILE *file = NULL;

	struct net_host host1;
	host1.seq = 100;
	host1.ether_host[0] = 0x2a;
	host1.addr = 0x6401A8C0;
	host1.port = 80;

	struct net_host host2;
	host2.seq = 200;
	host2.ether_host[0] = 0x1a;
	host2.addr = 0x6501A8C0;
	host2.port = 110;
	
	if (argc > 1) {
		file = fopen(argv[1], "wb");
	} else {
		file = fopen("generated.pcap", "wb");
	}

	if (!file) {
		perror("failed to open file");
		exit(1);
	}

	write_pcap_header(file);

	tcp_connect(file, &host1, &host2);

	send_data(file, &host1, &host2, "HELLO WORLD");
	send_data(file, &host2, &host1, "Did you say something?");

	tcp_disconnect(file, &host1, &host2);

	fclose(file);
	return 0;
}
