#ifndef __PP_H
#define __PP_H

#include <getopt.h>
#include <signal.h>
#include <netinet/in.h>

#include <pp_context.h>
#include <pp_fnct.h>
#include <pp_decap.h>
#include <pp_analyzer.h>
#include <pp_rest.h>
#include <pp_flowtop.h>
#include <pp_ndpi.h>

#include <pp_window_size.h>
#include <pp_bandwidth.h>
#include <pp_rtt.h>
#include <pp_application_filter.h>


#define PPVERSION "0.1"

int pp_parse_cmd_line(int argc, char **argv, struct pp_context *pp_ctx);

void pp_catch_sigusr1(int signal);
void pp_catch_sigusr2(int signal);
void pp_catch_term(int signal);

void pp_usage(void);
void pp_version(void);

#endif /* __PP_H */
