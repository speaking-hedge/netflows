#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

typedef struct net_host {
	int seq; // tcp sequence number
	u_char ether_host[6]; // mac address
	__u32 addr; // ip address
	__u16 port; // port
} net_host_t;