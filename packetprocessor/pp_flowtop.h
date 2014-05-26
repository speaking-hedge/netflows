#ifndef __PP_FLOWTOP
#define __PP_FLOWTOP

#include <ncurses.h>
#include <time.h>
#include <pthread.h>
#include <pp_context.h>
#include <pp_fnct.h>

enum pp_flowtop_sort_criteria {
	PP_FT_SORT_BY_NONE = 0,
	PP_FT_SORT_BY_ID,
	PP_FT_SORT_BY_L3,
	PP_FT_SORT_BY_L4,
	PP_FT_SORT_BY_L57,
	PP_FT_SORT_BY_SRC_ADDR,
	PP_FT_SORT_BY_DST_ADDR,
	PP_FT_SORT_BY_SRC_PORT,
	PP_FT_SORT_BY_DST_PORT,
	PP_FT_SORT_BY_PKT_UP,
	PP_FT_SORT_BY_PKT_DOWN,
	PP_FT_SORT_BY_BYT_UP,
	PP_FT_SORT_BY_BYT_DOWN,
	PP_FT_SORT_BY_AGE,
	PP_FT_SORT_BY_LAST_SEEN,
	PP_FT_SORT_BY_EOL
};

enum pp_flowtop_sort_order {
	PP_FT_SORT_ORDER_ASCENDING = 0,
	PP_FT_SORT_ORDER_DESCENDING,
	PP_FT_SORT_ORDER_EOL
};

struct pp_flowtop_header {
	char *str;
	uint8_t x_pos;
	uint8_t y_pos;
	uint8_t highlight_pos;
	char key;
	enum pp_flowtop_sort_criteria sort_key;
};

int pp_flowtop_init(struct pp_context *pp_ctx);
void pp_flowtop_destroy();
void pp_flowtop_header_print(struct pp_context *pp_ctx);
void pp_flowtop_flow_print(struct pp_context *pp_ctx);
void pp_flowtop_draw();

#endif
