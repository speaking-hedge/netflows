#include <pp_flowtop.h>

#define PP_FLOWTOP_HEADER_ROW_COUNT		3
static void *__pp_flowtop_keyhandler(void *arg);
static void __pp_flowtop_redraw_all(struct pp_context *pp_ctx);
static struct pp_flow_list_entry* __pp_flowtop_list_merge_sort_by_src_addr(struct pp_flow_list_entry *head);
static struct pp_flow_list_entry* __pp_flowtop_list_merge_by_src_addr(struct pp_flow_list_entry *a,
																	struct pp_flow_list_entry *b);
static struct pp_flow_list_entry* __pp_flowtop_list_merge_sort_by_dst_addr(struct pp_flow_list_entry *head);
static struct pp_flow_list_entry* __pp_flowtop_list_merge_by_dst_addr(struct pp_flow_list_entry *a,
																	struct pp_flow_list_entry *b);

static struct pp_flowtop_header __pp_ft_list_header[] = {
	{"id",                   0, 0, 0, 'i', PP_FT_SORT_BY_ID },
	{"l3",                   9, 0, 1, '3', PP_FT_SORT_BY_L3 },
	{"l4",                  18, 0, 1, '4', PP_FT_SORT_BY_L4 },
	{"l5..l7/application",  27, 0, 1, '5', PP_FT_SORT_BY_L57 },
	{"src addr",            49, 0, 0, 's', PP_FT_SORT_BY_SRC_ADDR },
	{"dst addr",            49, 1, 0, 'd', PP_FT_SORT_BY_DST_ADDR },
	{"Src port",            92, 0, 0, 'S', PP_FT_SORT_BY_SRC_PORT },
	{"Dst port",            92, 1, 0, 'D', PP_FT_SORT_BY_DST_PORT },
	{"pkt up",             103, 0, 0, 'p', PP_FT_SORT_BY_PKT_UP },
	{"Pkt down",           103, 1, 0, 'P', PP_FT_SORT_BY_PKT_DOWN },
	{"byte Up",            120, 0, 0, 'b', PP_FT_SORT_BY_BYT_UP },
	{"Byte Down",          120, 1, 0, 'B', PP_FT_SORT_BY_BYT_DOWN },
	{"Age",                137, 0, 0, 'A', PP_FT_SORT_BY_AGE},
	{"last seen",          137, 1, 0, 'l', PP_FT_SORT_BY_LAST_SEEN},
	{NULL, 0, 0}
};

/**
 * @brief return the center element of the list starting at given head
 * @param head of the list
 * @retval center node on success
 * @retval NULL if given list was empty
 */
struct pp_flow_list_entry* pp_flowtop_list_get_center_node(struct pp_flow_list_entry *head) {

	struct pp_flow_list_entry *fast_entry, *slow_entry;

	if (!head) {
		return NULL;
	}

	fast_entry = slow_entry = head;

	while (fast_entry->next && fast_entry->next->next) {
		slow_entry = slow_entry->next;
		fast_entry = fast_entry->next->next;
	}
	return slow_entry;
}

/* pp_flowtop_list_merge_by_NAME */
PP_FLOWTOP_LIST_MERGE_BY(first_seen, first_seen)
PP_FLOWTOP_LIST_MERGE_BY(data_downstream_bytes, data_downstream.bytes)
PP_FLOWTOP_LIST_MERGE_BY(data_upstream_bytes, data_upstream.bytes)
PP_FLOWTOP_LIST_MERGE_BY(ep_b_port, ep_b.port)
PP_FLOWTOP_LIST_MERGE_BY(id, id)
PP_FLOWTOP_LIST_MERGE_BY(protocols_l3, protocols[PP_OSI_LAYER_3])
PP_FLOWTOP_LIST_MERGE_BY(protocols_l4, protocols[PP_OSI_LAYER_4])
PP_FLOWTOP_LIST_MERGE_BY(ndpi_protocol, ndpi_protocol)
PP_FLOWTOP_LIST_MERGE_BY(last_seen, last_seen)
PP_FLOWTOP_LIST_MERGE_BY(data_downstream_packets, data_downstream.packets)
PP_FLOWTOP_LIST_MERGE_BY(data_upstream_packets, data_upstream.packets)
PP_FLOWTOP_LIST_MERGE_BY(ep_a_port, ep_a.port)

/* pp_flowtop_list_merge_sort_by_NAME */
PP_FLOWTOP_LIST_MERGE_SORT_BY(first_seen)
PP_FLOWTOP_LIST_MERGE_SORT_BY(data_downstream_bytes)
PP_FLOWTOP_LIST_MERGE_SORT_BY(data_upstream_bytes)
PP_FLOWTOP_LIST_MERGE_SORT_BY(ep_b_port)
PP_FLOWTOP_LIST_MERGE_SORT_BY(id)
PP_FLOWTOP_LIST_MERGE_SORT_BY(protocols_l3)
PP_FLOWTOP_LIST_MERGE_SORT_BY(protocols_l4)
PP_FLOWTOP_LIST_MERGE_SORT_BY(ndpi_protocol)
PP_FLOWTOP_LIST_MERGE_SORT_BY(last_seen)
PP_FLOWTOP_LIST_MERGE_SORT_BY(data_downstream_packets)
PP_FLOWTOP_LIST_MERGE_SORT_BY(data_upstream_packets)
PP_FLOWTOP_LIST_MERGE_SORT_BY(ep_a_port)

static struct pp_flow_list_entry* __pp_flowtop_list_merge_sort_by_src_addr(struct pp_flow_list_entry *head) {

	if(!head || !head->next) {
		return head;
	}

	struct pp_flow_list_entry* middle = pp_flowtop_list_get_center_node(head);
	struct pp_flow_list_entry* right = middle->next;

	middle->next = NULL;

	return __pp_flowtop_list_merge_by_src_addr(__pp_flowtop_list_merge_sort_by_src_addr(head),
											 __pp_flowtop_list_merge_sort_by_src_addr(right));
}

static struct pp_flow_list_entry* __pp_flowtop_list_merge_by_src_addr(struct pp_flow_list_entry *a,
																	struct pp_flow_list_entry *b) {
	struct pp_flow_list_entry tmp, *curr;
	curr = &tmp;

	while(a && b) {
		if ( memcmp(&a->flow->ep_a.ip.addr.v6, &b->flow->ep_a.ip.addr.v6, sizeof(struct in6_addr)) <= 0) {
			curr->next = a;
			a = a->next;
		} else {
			curr->next = b;
			b = b->next;
		}
		curr = curr->next;
	}

	curr->next = (!a) ? b : a;
	return tmp.next;
}

static struct pp_flow_list_entry* __pp_flowtop_list_merge_sort_by_dst_addr(struct pp_flow_list_entry *head) {

	if(!head || !head->next) {
		return head;
	}

	struct pp_flow_list_entry* middle = pp_flowtop_list_get_center_node(head);
	struct pp_flow_list_entry* right = middle->next;

	middle->next = NULL;

	return __pp_flowtop_list_merge_by_dst_addr(__pp_flowtop_list_merge_sort_by_dst_addr(head),
											   __pp_flowtop_list_merge_sort_by_dst_addr(right));
}

static struct pp_flow_list_entry* __pp_flowtop_list_merge_by_dst_addr(struct pp_flow_list_entry *a,
																	struct pp_flow_list_entry *b) {
	struct pp_flow_list_entry tmp, *curr;
	curr = &tmp;

	while(a && b) {
		if ( memcmp(&a->flow->ep_b.ip.addr.v6, &b->flow->ep_b.ip.addr.v6, sizeof(struct in6_addr)) <= 0) {
			curr->next = a;
			a = a->next;
		} else {
			curr->next = b;
			b = b->next;
		}
		curr = curr->next;
	}

	curr->next = (!a) ? b : a;
	return tmp.next;
}

/**
 * @brief return a sorted list of flows
 * @note the list must not be changed outside the function while in use
 * @brief list to be sorted
 * @brief size of the list
 * @brief by criteria to sort on
 * @brief order sort ascending or descanding
 * @retval const * const ptr to a sorted list
 * @retval NULL on error
 */
static void __pp_flowtop_sort_flow_list(struct pp_context *pp_ctx) {

	struct pp_flow_list_entry *entry, *prev = NULL;

	pthread_mutex_lock(&pp_ctx->flow_list_lock);

	if (!pp_ctx->flow_list.head) {
		pthread_mutex_unlock(&pp_ctx->flow_list_lock);
		return;
	}

	switch(pp_ctx->flowtop_sort_by) {
	case PP_FT_SORT_BY_AGE:
		pp_ctx->flow_list.head = CALL_PP_FLOWTOP_LIST_MERGE_SORT_BY(first_seen, pp_ctx->flow_list.head);
		break;
	case PP_FT_SORT_BY_BYT_DOWN:
		pp_ctx->flow_list.head = CALL_PP_FLOWTOP_LIST_MERGE_SORT_BY(data_downstream_bytes, pp_ctx->flow_list.head);
		break;
	case PP_FT_SORT_BY_BYT_UP:
		pp_ctx->flow_list.head = CALL_PP_FLOWTOP_LIST_MERGE_SORT_BY(data_upstream_bytes, pp_ctx->flow_list.head);
		break;
	case PP_FT_SORT_BY_DST_PORT:
		pp_ctx->flow_list.head = CALL_PP_FLOWTOP_LIST_MERGE_SORT_BY(ep_b_port, pp_ctx->flow_list.head);
		break;
	case PP_FT_SORT_BY_ID:
		pp_ctx->flow_list.head = CALL_PP_FLOWTOP_LIST_MERGE_SORT_BY(id, pp_ctx->flow_list.head);
		break;
	case PP_FT_SORT_BY_L3:
		pp_ctx->flow_list.head = CALL_PP_FLOWTOP_LIST_MERGE_SORT_BY(protocols_l3, pp_ctx->flow_list.head);
		break;
	case PP_FT_SORT_BY_L4:
		pp_ctx->flow_list.head = CALL_PP_FLOWTOP_LIST_MERGE_SORT_BY(protocols_l4, pp_ctx->flow_list.head);
		break;
	case PP_FT_SORT_BY_L57:
		pp_ctx->flow_list.head = CALL_PP_FLOWTOP_LIST_MERGE_SORT_BY(ndpi_protocol, pp_ctx->flow_list.head);
		break;
	case PP_FT_SORT_BY_LAST_SEEN:
		pp_ctx->flow_list.head = CALL_PP_FLOWTOP_LIST_MERGE_SORT_BY(last_seen, pp_ctx->flow_list.head);
		break;
	case PP_FT_SORT_BY_PKT_DOWN:
		pp_ctx->flow_list.head = CALL_PP_FLOWTOP_LIST_MERGE_SORT_BY(data_downstream_packets, pp_ctx->flow_list.head);
		break;
	case PP_FT_SORT_BY_PKT_UP:
		pp_ctx->flow_list.head = CALL_PP_FLOWTOP_LIST_MERGE_SORT_BY(data_upstream_packets, pp_ctx->flow_list.head);
		break;
	case PP_FT_SORT_BY_SRC_PORT:
		pp_ctx->flow_list.head = CALL_PP_FLOWTOP_LIST_MERGE_SORT_BY(ep_a_port, pp_ctx->flow_list.head);
		break;
	case PP_FT_SORT_BY_SRC_ADDR:
		pp_ctx->flow_list.head = __pp_flowtop_list_merge_sort_by_src_addr(pp_ctx->flow_list.head);
		break;
	case PP_FT_SORT_BY_DST_ADDR:
		pp_ctx->flow_list.head = __pp_flowtop_list_merge_sort_by_dst_addr(pp_ctx->flow_list.head);
		break;
	default:
		break;
	}

	/* recreated prev-links and tail-entry */
	entry = pp_ctx->flow_list.head;
	do {
		entry->prev = prev;
		prev = entry;
		entry = entry->next;
	} while(entry);
	pp_ctx->flow_list.tail = prev;

	pthread_mutex_unlock(&pp_ctx->flow_list_lock);
}

/**
 * @brief handle ncureses keypresses
 * @param arg ptr to the pp context
 * @retval NULL
 */
static void *__pp_flowtop_keyhandler(void *arg) {

	struct pp_context *pp_ctx = NULL;
	int c = 0, i = 0, sm = 0;

	assert(arg);

	pp_ctx = arg;

	while(1) {
		c = getch();
		switch(c) {
		case 'q':
		case 'Q':
			kill(getpid(), SIGTERM);
			break;
		case '+':
			if ((pp_ctx->flowtop_interval + 1 + pp_ctx->flowtop_interval/50)< 3600) {
				pp_ctx->flowtop_interval += 1 + pp_ctx->flowtop_interval/50;
			}
			pp_flowtop_header_print(pp_ctx);
			break;
		case '-':
			if (pp_ctx->flowtop_interval >= 2) {
				pp_ctx->flowtop_interval -= 1 + pp_ctx->flowtop_interval/50;
			}
			pp_flowtop_header_print(pp_ctx);
			break;
		case 'o':
		case 'O':
			if (pp_ctx->flowtop_sort_order == PP_FT_SORT_ORDER_ASCENDING) {
				pp_ctx->flowtop_sort_order = PP_FT_SORT_ORDER_DESCENDING;
			} else {
				pp_ctx->flowtop_sort_order = PP_FT_SORT_ORDER_ASCENDING;
			}
			__pp_flowtop_redraw_all(pp_ctx);
			break;
		default:
			i = 0;
			while (__pp_ft_list_header[i].str ) {
				if (__pp_ft_list_header[i].key == c &&
					pp_ctx->flowtop_sort_by != __pp_ft_list_header[i].sort_key) {
					pp_ctx->flowtop_sort_by = __pp_ft_list_header[i].sort_key;
					__pp_flowtop_redraw_all(pp_ctx);
					break;
				}
				i++;
			}
			break;
		}
	}

	return NULL;
}

/**
 * @brief redraw screen
 */
static void __pp_flowtop_redraw_all(struct pp_context *pp_ctx) {

	clear();
	pp_flowtop_header_print(pp_ctx);
	pp_flowtop_flow_print(pp_ctx);
	refresh();
}

/**
 * @brief init the ncurses environment and starts the keyhandler thread
 * @retval 0 on success
 * @retval 1 on error
 */
int pp_flowtop_init(struct pp_context *pp_ctx) {

	initscr();

	pp_ctx->flowtop_sort_by = PP_FT_SORT_BY_ID;
	pp_ctx->flowtop_sort_order = PP_FT_SORT_ORDER_ASCENDING;

	if(pthread_create(&pp_ctx->pt_flowtop_keyhandler, NULL, &__pp_flowtop_keyhandler, pp_ctx)) {
		return 1;
	}

	keypad(stdscr, TRUE);
	noecho();
	clear();
	refresh();

	return 0;
}

/**
 * @brief leave the ncurses environment
 */
void pp_flowtop_destroy() {

	clear();
	refresh();
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
	mvprintw(0,90,  "sort order:   %s (o)   ", pp_ctx->flowtop_sort_order == PP_FT_SORT_ORDER_ASCENDING?"asc":"desc");

	/* l1 */
	mvprintw(1,0,   "packets seen:  %d", pp_ctx->packets_seen);
	mvprintw(1,30,  "bytes seen:  %d", pp_ctx->bytes_seen);
	mvprintw(1,60,  "update:  %ds (+/-)      ", pp_ctx->flowtop_interval);
	/* l2 */
	mvprintw(2,0,   "packets taken: %d", pp_ctx->packets_taken);
	mvprintw(2,30,  "bytes taken: %d", pp_ctx->bytes_taken);
	mvprintw(2,60,  "running: %02d:%02d:%02d", b_now.tm_hour, b_now.tm_min, b_now.tm_sec);

	pthread_mutex_unlock(&pp_ctx->stats_lock);

	refresh();
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
	mvprintw(3,0,   "-------------------------------------------------------------------------------------------------------------------------------------------------------");

	i = 0;
	while (__pp_ft_list_header[i].str ) {

		if (__pp_ft_list_header[i].sort_key == PP_FT_SORT_BY_NONE) {
			mvprintw(PP_FLOWTOP_HEADER_ROW_COUNT + 1,
					 __pp_ft_list_header[i].x_pos,
					 "%s  ", __pp_ft_list_header[i].str);
			i++;
			continue;
		}

		if (pp_ctx->flowtop_sort_by == __pp_ft_list_header[i].sort_key) {
			mvprintw(PP_FLOWTOP_HEADER_ROW_COUNT + 1 + __pp_ft_list_header[i].y_pos,
				 __pp_ft_list_header[i].x_pos,
				 "[%s]", __pp_ft_list_header[i].str);

			mvchgat(PP_FLOWTOP_HEADER_ROW_COUNT + 1 + __pp_ft_list_header[i].y_pos,
				__pp_ft_list_header[i].x_pos,
				2 + strlen(__pp_ft_list_header[i].str),
				A_BOLD, 1, NULL);
		} else {
			mvprintw(PP_FLOWTOP_HEADER_ROW_COUNT + 1 + __pp_ft_list_header[i].y_pos,
					 __pp_ft_list_header[i].x_pos,
					 "%s  ", __pp_ft_list_header[i].str);

			mvchgat(PP_FLOWTOP_HEADER_ROW_COUNT + 1 + __pp_ft_list_header[i].y_pos,
				__pp_ft_list_header[i].x_pos + __pp_ft_list_header[i].highlight_pos,
				1, A_BOLD | A_UNDERLINE, 1, NULL);
		}

		i++;
	}

	mvprintw(6,0,   "-------------------------------------------------------------------------------------------------------------------------------------------------------");

	__pp_flowtop_sort_flow_list(pp_ctx);
	flow_entry = pp_ctx->flowtop_sort_order == PP_FT_SORT_ORDER_ASCENDING ? pp_ctx->flow_list.head : pp_ctx->flow_list.tail;

	getmaxyx(stdscr,row,col);
	row -= PP_FLOWTOP_HEADER_ROW_COUNT - 4;
	i = PP_FLOWTOP_HEADER_ROW_COUNT + 4;

	/* TODO: apply scrollable listbox */
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
		mvprintw(i, 0, "%05d", flow->id);

		/* l3 */
		pp_get_proto_name(PP_OSI_LAYER_3, flow->protocols[PP_OSI_LAYER_3], name_buf, 31);
		mvprintw(i, 9, "%s", name_buf);

		/* l4 */
		pp_get_proto_name(PP_OSI_LAYER_4, flow->protocols[PP_OSI_LAYER_4], name_buf, 31);
		mvprintw(i, 18, "%s", name_buf);

		/* l5..7 */
		pp_get_proto_name(PP_OSI_LAYER_4, flow->protocols[PP_OSI_LAYER_4], name_buf, 31);
		mvprintw(i, 27, "%s", pp_ndpi_get_protocol_name(pp_ctx, flow));

		/* src / dst */
		mvprintw(i, 49, "%s", ipsrc);
		mvprintw(i+1, 49, "%s", ipdst);

		/* src / dst port */
		mvprintw(i, 92, "%d", flow->ep_a.port);
		mvprintw(i+1, 92, "%d", flow->ep_b.port);

		/* packets send */
		mvprintw(i, 103, "%d", flow->data_upstream.packets);
		mvprintw(i+1, 103, "%d", flow->data_downstream.packets);

		/* bytes send */
		mvprintw(i, 120, "%d", flow->data_upstream.bytes);
		mvprintw(i+1, 120, "%d", flow->data_downstream.bytes);

		/* first seen */
		mvprintw(i, 137, "%" PRIu64, flow->first_seen);

		/* last seen */
		mvprintw(i+1, 137, "%" PRIu64, flow->last_seen);

		pthread_mutex_unlock(&flow->lock);

		i += 2;
		flow_entry = pp_ctx->flowtop_sort_order == PP_FT_SORT_ORDER_ASCENDING ? flow_entry->next : flow_entry->prev;
	}
}

/**
 * @brief redraw the ncurses surface
 */
void pp_flowtop_draw(struct pp_context *pp_ctx) {
	__pp_flowtop_redraw_all(pp_ctx);
}

