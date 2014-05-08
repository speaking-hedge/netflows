#include "pp.h"

int main(int argc, char **argv) {
    
    struct option options[] = {
		{"help", 0, NULL, 'h'},
		{"check", 1, NULL, 'c'},
		{NULL, 0, NULL, 0}
	};
    
    while (1) {
		switch(getopt_long(argc, argv, "hc:", options, NULL)) {
			case -1:
				break;
			case '?':
				return -1;
			case 'h':
				usage();
				return 0;
			break;
			case 'c':
				return check_file(optarg);
			break;
			default:
				abort();
		}
	}
    
	return 0;
}

/**
 * @brief check if given name points to a file we can open as a pcap(ng)
 * @param name of the file to test
 * @retval (0) if file is valid
 * @retval (1) if file is invalid
 */
int check_file(char *name) {
	
	char errbuf[PCAP_ERRBUF_SIZE] = {'\0'};
	pcap_t *handle = pcap_open_offline(name, errbuf);
	if (!handle) { 
		return 1; 
    }
    pcap_close(handle);
    
	return 0;
}

/**
 * @brief: output programs help text
 */
void usage(void) {
	printf("Usage: pp [OPTION] FILE\n");
	printf("processes network packets gathered from sniffed traffic to generate\n");
	printf("flow related statistics\n\n");
	printf("-c --check        check if given file is a valid pcap(ng) file\n");
	printf("-h --help         show help\n");
}
