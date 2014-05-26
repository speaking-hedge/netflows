#include <pp_flowtop.h>

#define PP_FLOWTOP_HEADER_ROW_COUNT		3

/**
 * @brief init the ncurses environment
 */
void pp_flowtop_init() {

	initscr();
	/*
	raw();
	keypad(stdscr, TRUE);
	*/
	noecho();
	clear();
}

/**
 * @brief leave the ncurses environment
 */
void pp_flowtop_destroy() {

	endwin();
}

/**
 * @brief output configuration and basic stats
 * @param pp_ctx the context to print the informations for
 */
void pp_flowtop_header_print(struct pp_context *pp_ctx) {

	static uint8_t init = 1;
	static time_t start_t = 0;
	time_t now;
	struct tm b_now;

	if (init) {
		time(&start_t);
		init = 0;
	}
	time(&now);
	now -= start_t;
	gmtime_r(&now, &b_now);

	pthread_mutex_lock(&pp_ctx->stats_lock);

	/* l0 */
	mvprintw(0,0,   "interface:     %s", pp_ctx->packet_source);
	mvprintw(0,30,  "filtered:    %s", pp_ctx->bp_filter?"yes":"no");
	mvprintw(0,60,  "flows:   %d", pp_ctx->unique_flows);
	/* l1 */
	mvprintw(1,0,   "packets seen:  %d", pp_ctx->packets_seen);
	mvprintw(1,30,  "bytes seen:  %d", pp_ctx->bytes_seen);
	mvprintw(1,60,  "update:  %ds (+/-)", pp_ctx->flowtop_interval);
	/* l2 */
	mvprintw(2,0,   "packets taken: %d", pp_ctx->packets_taken);
	mvprintw(2,30,  "bytes taken: %d", pp_ctx->bytes_taken);
	mvprintw(2,60,  "running: %02d:%02d:%02d", b_now.tm_hour, b_now.tm_min, b_now.tm_sec);

	pthread_mutex_unlock(&pp_ctx->stats_lock);
}

/**
 * @brief output flow related informations
 * @param pp_ctx the context to print the informations for
 * @note this uses the flow_list stored in the pp context
 * @todo add and apply sort criteria
 */
void pp_flowtop_flow_print(struct pp_context *pp_ctx) {

	struct pp_flow_list_entry *flow_entry = NULL;
	struct pp_flow *flow = NULL;
	int row,col, i;
	char ipsrc[INET6_ADDRSTRLEN];
	char ipdst[INET6_ADDRSTRLEN];
	char name_buf[32];

	/* l3..5 */
	mvprintw(3,0,   "------------------------------------------------------------------------------------------------------------------------------------");
	mvprintw(4,0,   "id      l3    l4   l5..l7/application  src/dst                                  port   packets send   bytes send     last seen");
	mvprintw(5,0,   "------------------------------------------------------------------------------------------------------------------------------------");

	getmaxyx(stdscr,row,col);
	row -= PP_FLOWTOP_HEADER_ROW_COUNT - 3;
	i = PP_FLOWTOP_HEADER_ROW_COUNT + 3;

	pthread_mutex_lock(&pp_ctx->flow_list_lock);

	flow_entry = pp_ctx->flow_list.head;

	/* TODO: apply sort criteria */
	/* TODO: apply scollable listbox */
	while(flow_entry && i < row) {

		flow = flow_entry->flow;

		pthread_mutex_lock(&flow->lock);

		if (flow->protocols[PP_OSI_LAYER_3] == ETH_P_IP) {
			inet_ntop(AF_INET, &(flow->ep_a.ip.addr.v6), ipsrc, INET6_ADDRSTRLEN);
			inet_ntop(AF_INET, &(flow->ep_b.ip.addr.v6), ipdst, INET6_ADDRSTRLEN);
		} else {
			inet_ntop(AF_INET6, &(flow->ep_a.ip.addr.v6), ipsrc, INET6_ADDRSTRLEN);
			inet_ntop(AF_INET6, &(flow->ep_b.ip.addr.v6), ipdst, INET6_ADDRSTRLEN);
		}

		/* id */
		mvprintw(i,0, "%05d", flow->id);

		/* l3 */
		pp_get_proto_name(PP_OSI_LAYER_3, flow->protocols[PP_OSI_LAYER_3], name_buf, 31);
		mvprintw(i,8, "%s", name_buf);

		/* l4 */
		pp_get_proto_name(PP_OSI_LAYER_4, flow->protocols[PP_OSI_LAYER_4], name_buf, 31);
		mvprintw(i,14, "%s", name_buf);

		/* l5..7 */
		pp_get_proto_name(PP_OSI_LAYER_4, flow->protocols[PP_OSI_LAYER_4], name_buf, 31);
		mvprintw(i,19, "<unused>");

		/* src / dst */
		mvprintw(i,39, "%s", ipsrc);
		mvprintw(i+1,39, "%s", ipdst);

		/* src / dst port */
		mvprintw(i,80, "%d", flow->ep_a.port);
		mvprintw(i+1,80, "%d", flow->ep_b.port);

		/* packets send */
		mvprintw(i,87, "%d", flow->data_upstream.packets);
		mvprintw(i+1,87, "%d", flow->data_downstream.packets);

		/* bytes send */
		mvprintw(i,102, "%d", flow->data_upstream.bytes);
		mvprintw(i+1,102, "%d", flow->data_downstream.bytes);

		/* last seen */
		mvprintw(i,117, "%d", flow->last_seen);

		pthread_mutex_unlock(&flow->lock);

		i += 2;
		flow_entry = flow_entry->next;
	}

	pthread_mutex_unlock(&pp_ctx->flow_list_lock);
}

/**
 * @brief redraw the ncurses surface
 */
void pp_flowtop_draw() {
	refresh();
}
