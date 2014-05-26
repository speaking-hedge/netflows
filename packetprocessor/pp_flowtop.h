#ifndef __PP_FLOWTOP
#define __PP_FLOWTOP

#include <ncurses.h>
#include <time.h>
#include <pp_context.h>
#include <pp_fnct.h>

void pp_flowtop_init();
void pp_flowtop_destroy();
void pp_flowtop_header_print(struct pp_context *pp_ctx);
void pp_flowtop_flow_print(struct pp_context *pp_ctx);
void pp_flowtop_draw();

#endif
