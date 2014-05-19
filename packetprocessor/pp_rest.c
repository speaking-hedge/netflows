#include "pp_rest.h"

/**
 * @brief send data to server
 * @param url url to connect to
 * @retval 0 on success
 * @retval 1 on error
 */
static int __pp_rest_send(const char* url)
{
	CURL *rest = curl_easy_init();

	/* failed to init curl? */
	if (!rest) return 1;

	/* set url */
	curl_easy_setopt(rest, CURLOPT_URL, url);

	/* send it */
	CURLcode result = curl_easy_perform(rest);

	/* tidy up */
	curl_easy_cleanup(rest);

	/* check for errors */
	if(result != CURLE_OK) {
		fprintf(stderr, "REST connection failed: %s\n", curl_easy_strerror(result));
		return 1;
	}

	curl_global_cleanup();
	return 0;
}

/**
 * @brief set job state to running
 * @param url to connect to
 * @param job_hash id of the job
 * @param state job state //TODO: Is there an ENUM yet?
 * @retval 0 on success
 * @retval 1 on error
 */
int pp_rest_job_state(const char* url, const char* job_hash, const char state)
{
	if (state > 6 || state < 0) return 1; // invalid state id

	char *suffix = "/accessjobs/updateState?";
	char param_stateid[] = "stateid=0";
	char *param_jobid = "&jobid=";

	char msg[strlen(url) + strlen(suffix) + strlen(param_stateid) + strlen(param_jobid) + strlen(job_hash) + 1];

	param_stateid[8] = (char)(48+state); // cheap convert

	strcpy(msg, url);
	strcat(msg, suffix);
	strcat(msg, param_stateid);
	strcat(msg, param_jobid);
	strcat(msg, job_hash);
	return __pp_rest_send(msg);
}
