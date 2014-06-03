#ifndef __PP_NDPI
#define __PP_NDPI

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>
#include <stdarg.h>
#include <search.h>
#include <pcap.h>
#include <signal.h>

#include <linux_compat.h>
#include <ndpi_main.h>

#include <pp_context.h>

#define PP_NDPI_TICKS_RESOLUTION	1000

int pp_ndpi_init(struct pp_context *pp_ctx);
void pp_ndpi_destroy(struct pp_context *pp_ctx);
int pp_ndpi_flow_attach(struct pp_flow *flow_ctx, struct pp_packet_context *pck_ctx);
const char* pp_ndpi_get_protocol_name(struct pp_context *pp_ctx, uint32_t protocol_id);
uint32_t pp_ndpi_get_protocol_id(struct pp_context *pp_ctx, const char *protocol_name);
int pp_ndpi_get_protocol_list(struct pp_context *pp_ctx, char *** protocol_list);
void pp_ndpi_stats_dump(struct pp_context *pp_ctx);

#endif /* __PP_NDPI */
