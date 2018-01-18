/****************************************************************************
 *
 * Copyright 2017 Samsung Electronics All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 ****************************************************************************/

#include "rt_request.h"
#include "rt_utils.h"

#define TAG "RT_REQ"

ocf_request_query_set_s *ocf_request_get_queries(ocf_request_s req)
{
	RT_VERIFY_NON_NULL_RET(req, TAG, "request", NULL);
	rt_request_s *request = (rt_request_s *) req;
	return &request->queries;
}

ocf_result_t ocf_request_get_send(ocf_endpoint_s *endpoint, const char *uri_path, const char *query, bool receive_ack, request_callback callback)
{
	return rt_request_get_send(endpoint, uri_path, query, receive_ack, callback);
}

ocf_result_t ocf_request_put_send(ocf_endpoint_s *endpoint, const char *uri_path, const char *query, ocf_rep_encoder_s rep, bool receive_ack, request_callback callback)
{
	return rt_request_put_send(endpoint, uri_path, query, (rt_rep_encoder_s *) rep, receive_ack, callback);
}

ocf_result_t ocf_request_post_send(ocf_endpoint_s *endpoint, const char *uri_path, const char *query, ocf_rep_encoder_s rep, bool receive_ack, request_callback callback)
{
	return rt_request_post_send(endpoint, uri_path, query, (rt_rep_encoder_s *) rep, receive_ack, callback);
}

ocf_result_t ocf_request_delete_send(ocf_endpoint_s *endpoint, const char *uri_path, const char *query, ocf_rep_encoder_s rep, bool receive_ack, request_callback callback)
{
	return rt_request_delete_send(endpoint, uri_path, query, (rt_rep_encoder_s *) rep, receive_ack, callback);
}

ocf_result_t ocf_response_send(const ocf_request_s req, ocf_rep_encoder_s rep, ocf_response_result_t eh_result)
{
	return rt_response_send((rt_request_s *) req, (rt_rep_encoder_s *) rep, eh_result);
}

ocf_result_t ocf_separate_accept(const ocf_request_s req, ocf_request_s separate_store)
{
	return rt_separate_accept((rt_request_s *) req, (rt_request_s *) separate_store);
}

ocf_result_t ocf_separate_resume(ocf_request_s separate_store, ocf_rep_encoder_s rep, ocf_response_result_t eh_result)
{
	return rt_separate_resume((rt_request_s *) separate_store, (rt_rep_encoder_s *) rep, eh_result);
}

ocf_result_t ocf_discovery(discovery_callback callback, const char *query)
{
	return rt_discovery(callback, query);
}
