#ifndef __PP_REST
#define __PP_REST

#include <string.h>
#include <curl/curl.h>
 
int rest_job_state(const char* url, const char* job_hash, const char state);
 
#endif /* __PP_REST */
