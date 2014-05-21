#ifndef __PP_REST
#define __PP_REST

#include <string.h>
#include <curl/curl.h>

enum RestJobState {
	JOB_STATE_FINISHED,
	JOB_STATE_TRUNCATED,
	JOB_STATE_RUNNING,
	JOB_STATE_CREATED,
	JOB_STATE_WAITING,
	JOB_STATE_FILE_ERROR,
	JOB_STATE_INTERNAL_ERROR
};

int pp_rest_job_state(const char* url, const char* job_hash, enum RestJobState state);

#endif /* __PP_REST */
