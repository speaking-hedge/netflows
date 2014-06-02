#ifndef __PP_REST
#define __PP_REST

#include <string.h>
#include <curl/curl.h>
#include <stdint.h>
#include <jansson.h>
#include <pp_flow.h>

enum RestJobState {
	JOB_STATE_FINISHED,
	JOB_STATE_TRUNCATED,
	JOB_STATE_RUNNING,
	JOB_STATE_CREATED,
	JOB_STATE_WAITING,
	JOB_STATE_FILE_ERROR,
	JOB_STATE_INTERNAL_ERROR
};
 
struct ReadMessage {
  const char *readptr;
  long sizeleft;
};

int pp_rest_job_state(const char* url, const char* job_hash, enum RestJobState state);
int pp_rest_job_state_msg(const char* url, const char* job_hash, enum RestJobState state, char* error);
int pp_rest_post_analyze_data(const char* url, const char* job_hash, uint32_t analyzer_id, uint32_t flow_id, int sample_id, const char* data);
int pp_rest_add_flow(const char* url, const char* job_hash, const struct pp_flow* flow);

#endif /* __PP_REST */
