#ifndef __PP_H
#define __PP_H

#include <getopt.h>
#include <signal.h>
#include <netinet/in.h>

#include <pp_common.h>
#include <pp_fnct.h>
#include <pp_analyse.h>


#define PPVERSION "0.1"

void pp_parse_cmd_line(int argc, char **argv, struct pp_config *pp_ctx);

void pp_catch_dump(int signal);
void pp_catch_term(int signal);

void pp_usage(void);
void pp_version(void);

#endif /* __PP_H */
