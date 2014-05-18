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

#include <pp_common.h>
#include <pp_context.h>

int pp_init_ctx(struct pp_config *pp_ctx, void (*packet_handler)(struct pp_config *pp_ctx, uint8_t *data, uint16_t len, uint64_t timestamp));
void pp_cleanup_ctx(struct pp_config *pp_ctx);
int pp_check_file(struct pp_config *pp_ctx);

void pp_dump_state(struct pp_config *pp_ctx);

int pp_pcap_open(struct pp_config *pp_ctx);
int pp_pcap_close(struct pp_config *pp_ctx);

int pp_live_start(struct pp_config *pp_ctx);
int pp_live_capture(struct pp_config *pp_ctx, volatile int *run, volatile int *dump);
int pp_live_shutdown(struct pp_config *pp_ctx);

int pp_get_proto_name(uint layer, uint32_t protocol, char* buf, size_t buf_len);

#endif /* __PP_FNTC_H */
