#include <stdio.h>
#include <pcap.h>

int main(int argc, char **argv) {
	
	pcap_t *hdl = NULL; 
    char errbuf[PCAP_ERRBUF_SIZE] = {'\0'};
    struct pcap_pkthdr hdr;
    const u_char *pkt = NULL;
    int i = 0;
    
    if (argc < 2) {
		fprintf(stderr, "missing parameter pcap-file - abort.\n");
		return -1;
	}
    
    if (!(hdl = pcap_open_offline(argv[1], errbuf))) { 
		fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf); 
		return -2; 
    } 

    while (pkt = pcap_next(hdl,&hdr)) { 
		printf("%04d - ts:%08lu ms size:%d byte (full cap:%s)\n", i, (hdr.ts.tv_sec * 1000) + (hdr.ts.tv_usec / 1000), hdr.caplen, hdr.caplen == hdr.len ?"yes":"no");
		i++;
	}
	return 0;
}
