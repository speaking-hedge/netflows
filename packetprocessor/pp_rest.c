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
	json_t *root, *status, *message;
	json_error_t error;
	const char *status_text;

	// add nullpointer at end of read bytes to terminate string
	*(ptr + nmemb) = '\0';

	root = json_loads(ptr, 0, &error);

	if(!root)
	{
		fprintf(stderr, "REST response JSON error: on line %d: %s\n", error.line, error.text);
		*(char *)userdata = 1; // maybe change this to error message
	}

	status = json_object_get(root, "status");
	if(json_is_string(status))
	{
		if (!strcmp(json_string_value(status), "Error")) {
			*(char *)userdata = 1;
			message = json_object_get(root, "message");
			if (json_is_string(message)) {
				fprintf(stderr, "REST response error: %s\n", json_string_value(message));
			} else {
				fprintf(stderr, "unknown REST response error\n");
			}
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
	char error = 0;

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
 * @brief add flow to DB
 * @param url to connect to
 * @param job_hash id of the job
 * @param flow to be put on data
 * @retval 0 on success
 * @retval 1 on error
 */
int pp_rest_add_flow(const char* url, const char* job_hash, const struct pp_flow* flow) {
	char *suffix = "/accessflows/insertflow?";
	char *param_id = "id="; // BUG: flow-id is not unique between jobs. Change DB to primary key ID & JOB_ID ?
	char *param_jobid = "&job_id=";
	char *param_endpt_a_ip = "&endpt_a_ip=";
	char *param_endpt_b_ip = "&endpt_b_ip=";
	char *param_endpt_a_port = "&endpt_a_port=";
	char *param_endpt_b_port = "&endpt_b_port=";

	char id_str[11];
	sprintf(id_str, "%d", flow->id);

	char endpt_a_port[6];
	sprintf(endpt_a_port, "%d", flow->ep_a.port);

	char endpt_b_port[6];
	sprintf(endpt_b_port, "%d", flow->ep_b.port);

	char endpt_a_ip[INET6_ADDRSTRLEN];
	if (flow->ep_a.ip.version == ETH_P_IPV6) { // BUG: version is always 0
		inet_ntop(AF_INET6, &(flow->ep_a.ip.addr.v6), endpt_a_ip, INET6_ADDRSTRLEN);
	} else {
		inet_ntop(AF_INET, &(flow->ep_a.ip.addr.v4), endpt_a_ip, INET_ADDRSTRLEN);
	}

	char endpt_b_ip[INET6_ADDRSTRLEN];
	if (flow->ep_b.ip.version == ETH_P_IPV6) {
		inet_ntop(AF_INET6, &(flow->ep_b.ip.addr.v6), endpt_b_ip, INET6_ADDRSTRLEN);
	} else {
		inet_ntop(AF_INET, &(flow->ep_b.ip.addr.v4), endpt_b_ip, INET_ADDRSTRLEN);
	}

	char msg[
		strlen(url) + strlen(suffix) +
		strlen(param_id) + strlen(id_str) +
		strlen(param_jobid) + strlen(job_hash) +
		strlen(param_endpt_a_ip) + strlen(endpt_a_ip) +
		strlen(param_endpt_b_ip) + strlen(endpt_b_ip) +
		strlen(param_endpt_a_port) + strlen(endpt_a_port) +
		strlen(param_endpt_b_port) + strlen(endpt_b_port) +
		1];

	strcpy(msg, url);
	strcat(msg, suffix);
	strcat(msg, param_id);
	strcat(msg, id_str);
	strcat(msg, param_jobid);
	strcat(msg, job_hash);
	strcat(msg, param_endpt_a_ip);
	strcat(msg, endpt_a_ip);
	strcat(msg, param_endpt_a_port);
	strcat(msg, endpt_a_port);
	strcat(msg, param_endpt_b_ip);
	strcat(msg, endpt_b_ip);
	strcat(msg, param_endpt_b_port);
	strcat(msg, endpt_b_port);

	return __pp_rest_send(msg);
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

/**
 * @brief upload analyzer data
 * @param url to connect to
 * @param flow_id id of the flow
 * @param sample_id id of the sample
 * @param data data to be uploaded
 * @retval 0 on success
 * @retval 1 on error
 */
int pp_rest_post_analyze_data(const char* url, const char* job_hash, uint32_t analyzer_id, uint32_t flow_id, int sample_id, const char* data) {
	char *suffix = "/accessresults/addresult?";
	char *param_jobid="job_id=";
	char *param_flowid="&flow_id=";
	char *param_analyzer_id="&analyzer_id=";
	char *param_snapshot_id="&snapshot_id=";
	char *param_data="&data=";

	char post_url[strlen(url) + strlen(suffix) + 1]; // POST url/accessresults/addressresult
	strcpy(post_url, url);
	strcat(post_url, suffix);

	char flow_id_str[11];
	sprintf(flow_id_str, "%d", flow_id);
	char sample_id_str[11];
	sprintf(sample_id_str, "%d", sample_id);
	char analyzer_id_str[4];
	sprintf(analyzer_id_str, "%d", analyzer_id);
	
	char post_data[
		strlen(param_jobid) + strlen(job_hash) +
		strlen(param_analyzer_id) + strlen(analyzer_id_str) +
		strlen(param_flowid) + strlen(flow_id_str) +
		strlen(param_snapshot_id) + strlen(sample_id_str) + 
		strlen(param_data) + strlen(data) + 1
	];
	strcpy(post_data, param_jobid);         // job_id = 
	strcat(post_data, job_hash);
	strcat(post_data, param_analyzer_id);   // analyzer_id = 
	strcat(post_data, analyzer_id_str);
	strcat(post_data, param_flowid);       // flow_id = 
	strcat(post_data, flow_id_str);
	strcat(post_data, param_snapshot_id);   // snapshot_id =
	strcat(post_data, sample_id_str);
	strcat(post_data, param_data);          // data = 
	strcat(post_data, data);

	return __rest_post(post_url, post_data);

}
