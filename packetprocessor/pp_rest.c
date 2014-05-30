#include "pp_rest.h"

static size_t __read_message( char *ptr, size_t size, size_t nmemb, void *userdata)
{
	struct ReadMessage *msg = (struct ReadMessage *)userdata;

	if(size*nmemb < 1) return 0; // out of memory

	if(msg->sizeleft) {
		*(char *)ptr = msg->readptr[0];
		msg->readptr++;
		msg->sizeleft--;
		return 1;
	}

	return 0;
}

/**
 * @brief interpret REST answer
 * @param *ptr pointer to the servers answer
 * @param size size of the answer
 * @param nmemb size again
 * @param *userdata error flag
 */
static size_t __answer_parser( char *ptr, size_t size, size_t nmemb, void *userdata) {
	// TODO: doc says ptr is not null terminated
	//       program says it is
	// TODO: code below is very ugly
	if (strstr(ptr, "\"status\":\"Error\""))
	{
		*(char *)userdata = 1;
		char *msg = strstr(ptr, "\"message\":");
		if (msg)
		{
			msg += 10;
			fprintf(stderr, "REST error: ");
			fprintf(stderr, msg);
			fprintf(stderr, "\n");
		} else {
			fprintf(stderr, "unknown REST error.\n");
		}
	}
	return size * nmemb;
}

/**
 * @brief send data to server
 * @param url url to connect to
 * @retval 0 on success
 * @retval 1 on error
 */
static int __pp_rest_send(const char* url) {
	CURL *rest = curl_easy_init();
	char error = 0;
	
	/* failed to init curl? */
	if (!rest) return 1;

	/* set url */
	curl_easy_setopt(rest, CURLOPT_URL, url);
	
	curl_easy_setopt(rest, CURLOPT_WRITEFUNCTION, __answer_parser);
	curl_easy_setopt(rest, CURLOPT_WRITEDATA, &error);

	/* send it */
	CURLcode result = curl_easy_perform(rest);

	/* tidy up */
	curl_easy_cleanup(rest);

	/* check for errors */
	if(result != CURLE_OK) {
		fprintf(stderr, "REST connection failed: %s\n", curl_easy_strerror(result));
		return 1;
	}
	if (error) {
		return 1;
	}

	curl_global_cleanup();
	return 0;
}

/**
 * @brief post data to server
 * @param url url to connect to
 * @param msg message to send
 * @retval 0 on success
 * @retval 1 on error
 */
static int __rest_post(const char* url, const char *data)
{
	CURL *rest = curl_easy_init();

	/* failed to init curl? */
	if (!rest) return 1;

	struct ReadMessage msg;
	msg.readptr = data;
	msg.sizeleft = (long)strlen(data);

	/* set url */
	curl_easy_setopt(rest, CURLOPT_URL, url);

	/* POST */ 
	curl_easy_setopt(rest, CURLOPT_POST, 1L);

    /* read data */ 
	curl_easy_setopt(rest, CURLOPT_READFUNCTION, __read_message);
	curl_easy_setopt(rest, CURLOPT_READDATA, &msg);
	curl_easy_setopt(rest, CURLOPT_POSTFIELDSIZE, msg.sizeleft);
	
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
 * @param state job state
 * @param error message
 * @retval 0 on success
 * @retval 1 on error
 */
int pp_rest_job_state_msg(const char* url, const char* job_hash, enum RestJobState state, char* error) {
	if (state > 6) return 1;

	char *suffix = "/accessjobs/updateState?";
	char param_stateid[] = "stateid=0";
	char *param_jobid = "&jobid=";
	char *param_msg = "&msg=";

	char msg[strlen(url) + strlen(suffix) + strlen(param_stateid) + strlen(param_jobid) + strlen(job_hash) + strlen(param_msg) + strlen(error) + 1];

	param_stateid[8] = (char)(48+state); // cheap convert

	strcpy(msg, url);
	strcat(msg, suffix);
	strcat(msg, param_stateid);
	strcat(msg, param_jobid);
	strcat(msg, job_hash);
	strcat(msg, param_msg);
	strcat(msg, error);

	return __pp_rest_send(msg);
}

/**
 * @brief set job state to running
 * @param url to connect to
 * @param job_hash id of the job
 * @param state job state
 * @retval 0 on success
 * @retval 1 on error
 */
int pp_rest_job_state(const char* url, const char* job_hash, enum RestJobState state) {
	if (state > 6) return 1;

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
