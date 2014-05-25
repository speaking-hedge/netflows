#ifndef __PP_FNTC_H
#define __PP_FNTC_H

#include <sys/capability.h>
#include <sys/socket.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <poll.h>
#include <time.h>
#include <gcrypt.h>
#include <signal.h>

#include <pp_context.h>

extern int ppoll(struct pollfd *fds, nfds_t nfds, const struct timespec *timeout_ts, const sigset_t *sigmask);

int pp_ctx_init(struct pp_context *pp_ctx, void (*packet_handler)(struct pp_context *pp_ctx, uint8_t *data, uint16_t len, uint64_t timestamp));
void pp_ctx_cleanup(struct pp_context *pp_ctx);
int pp_check_file(struct pp_context *pp_ctx);

void pp_dump_state(struct pp_context *pp_ctx);

int pp_pcap_open(struct pp_context *pp_ctx);
int pp_pcap_close(struct pp_context *pp_ctx);

int pp_live_init(struct pp_context *pp_ctx);
int pp_live_start(struct pp_context *pp_ctx);
int pp_live_capture(struct pp_context *pp_ctx, volatile int *run);
int pp_live_shutdown(struct pp_context *pp_ctx);

int pp_get_proto_name(uint layer, uint32_t protocol, char* buf, size_t buf_len);

/* TODO: reuinte pp.c and pp_fnct.c and make this functions static */
void pp_detach_analyzers_from_flow(struct pp_context *pp_ctx, struct pp_flow *flow_ctx);
int pp_attach_analyzers_to_flow(struct pp_context *pp_ctx, struct pp_flow *flow_ctx);

#endif /* __PP_FNTC_H */
