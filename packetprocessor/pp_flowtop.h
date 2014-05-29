#ifndef __PP_FLOWTOP
#define __PP_FLOWTOP

#include <ncurses.h>
#include <time.h>
#include <pthread.h>
#include <pp_context.h>
#include <pp_fnct.h>
#include <pp_ndpi.h>

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
void pp_flowtop_draw(struct pp_context *pp_ctx);

/* adapted from http://www.dontforgettothink.com/2011/11/23/merge-sort-of-linked-list/ */
#define __PP_FLOWTOP_LIST_MERGE_SORT_BY(NAME) \
struct pp_flow_list_entry* pp_flowtop_list_merge_sort_by_ ## NAME (struct pp_flow_list_entry *head) {	\
	if(!head || !head->next) {																			\
		return head;																					\
	}																									\
	struct pp_flow_list_entry* middle = pp_flowtop_list_get_center_node(head);							\
	struct pp_flow_list_entry* right = middle->next;													\
	middle->next = NULL;																				\
	return pp_flowtop_list_merge_by_ ## NAME ( pp_flowtop_list_merge_sort_by_ ## NAME (head), 			\
											   pp_flowtop_list_merge_sort_by_ ## NAME (right) ); 		\
}

#define PP_FLOWTOP_LIST_MERGE_SORT_BY(NAME) __PP_FLOWTOP_LIST_MERGE_SORT_BY(NAME)

#define CALL_PP_FLOWTOP_LIST_MERGE_SORT_BY(NAME, head)	\
pp_flowtop_list_merge_sort_by_ ## NAME( head);

#define __PP_FLOWTOP_LIST_MERGE_BY(NAME, CRITERIA) \
struct pp_flow_list_entry* pp_flowtop_list_merge_by_ ## NAME (struct pp_flow_list_entry *a,				\
															  struct pp_flow_list_entry *b) {			\
	struct pp_flow_list_entry tmp, *curr;																\
	curr = &tmp;																						\
	while(a && b) {																						\
		if(a->flow->CRITERIA <= b->flow->CRITERIA ) {													\
			curr->next = a;																				\
			a = a->next;																				\
		} else {																						\
			curr->next = b;																				\
			b = b->next;																				\
		}																								\
		curr = curr->next;																				\
	}																									\
	curr->next = (!a) ? b : a;																			\
	return tmp.next;																					\
}

#define PP_FLOWTOP_LIST_MERGE_BY(NAME, CRITERIA) __PP_FLOWTOP_LIST_MERGE_BY(NAME, CRITERIA)

#endif
