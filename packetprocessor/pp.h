#ifndef __PP_H
#define __PP_H

#include <getopt.h>
#include <signal.h>

#include <pp_common.h>
#include <pp_fnct.h>

#include <netinet/in.h>

#define PPVERSION "0.1"

struct nread_ip {
    u_int8_t        ip_vhl;          /* header length, version    */
#define IP_V(ip)    (((ip)->ip_vhl & 0xf0) >> 4)
#define IP_HL(ip)   ((ip)->ip_vhl & 0x0f)
    u_int8_t        ip_tos;          /* type of service           */
    u_int16_t       ip_len;          /* total length              */
    u_int16_t       ip_id;           /* identification            */
    u_int16_t       ip_off;          /* fragment offset field     */
#define IP_DF 0x4000                 /* dont fragment flag        */
#define IP_MF 0x2000                 /* more fragments flag       */
#define IP_OFFMASK 0x1fff            /* mask for fragmenting bits */
    u_int8_t        ip_ttl;          /* time to live              */
    u_int8_t        ip_p;            /* protocol                  */
    u_int16_t       ip_sum;          /* checksum                  */
    struct  in_addr ip_src, ip_dst;  /* source and dest address   */
};

void pp_parse_cmd_line(int argc, char **argv, struct pp_config *pp_ctx);

void pp_catch_dump(int signal);
void pp_catch_term(int signal);

void pp_usage(void);
void pp_version(void);

#endif /* __PP_H */
