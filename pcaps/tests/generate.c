#include "generate.h"

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

void write_packet_header(FILE *file, size_t len, size_t timeadd)
{
	struct tm time; // date doen't matter
	time.tm_sec = (timeadd/1000000);
	time.tm_min = 0;
	time.tm_hour = 12;
	time.tm_mday = 1;
	time.tm_mon = 1;
	time.tm_year = 114;
	time_t t = mktime(&time);
	
	struct pcaprec_hdr_s pac_header;
	pac_header.ts_sec = t;
	pac_header.ts_usec = timeadd%1000000;
	pac_header.incl_len = len;
	pac_header.orig_len = len;
	fwrite(&pac_header, sizeof(struct pcaprec_hdr_s), 1, file);
}

void write_layer2(FILE *file)
{
	struct ether_header layer2;
	layer2.ether_dhost[0] = 0xa; // garbage mac adress
	layer2.ether_shost[0] = 0xb;
	layer2.ether_type = htons(ETH_P_IP);
	fwrite(&layer2, sizeof(struct ether_header), 1, file);
}

void write_layer3_ip4(FILE *file, size_t len)
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
	layer3.saddr = 0x0100007f; // 127.0.0.1
	layer3.daddr = 0x0100007f;
	
	fwrite(&layer3, sizeof(struct iphdr), 1, file);
}

void write_layer4_tcp(FILE *file)
{
	struct tcphdr layer4;
	layer4.th_sport = htons(80);
	layer4.th_dport = htons(80);
	layer4.th_seq = 0;
	layer4.th_ack = 0;
	layer4.th_off = 5;
	layer4.th_flags = 0;
	layer4.th_win = 1;
	layer4.th_sum = 0; // who cares!
	layer4.th_urp = 0; // urgent... as if
	fwrite(&layer4, sizeof(struct tcphdr), 1, file);
}

int main() {
	FILE *file;
	file = fopen("generated.pcap","wb");

	char *data = "HELLO WORLD!";
	
	write_pcap_header(file);
	
	write_packet_header(file, sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(data), 0);
	
	write_layer2(file);
	
	write_layer3_ip4(file, sizeof(struct iphdr) + sizeof(struct tcphdr) + sizeof(data));

	write_layer4_tcp(file);

	fwrite(data, sizeof(data), 1, file);

	fclose(file);
	return 0;
	
}
