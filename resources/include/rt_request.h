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

#ifndef RESOURCE_RT_REQUEST_H_
#define RESOURCE_RT_REQUEST_H_

#include "ocf_request.h"

typedef struct _rt_data_s rt_data_s;
typedef struct _rt_rep_encoder_s rt_rep_encoder_s;

typedef struct _rt_request_s {
	const ocf_endpoint_s *endpoint;
	const rt_data_s *data;
	ocf_request_query_set_s queries;
	ocf_message_type_t msg_type;
} rt_request_s;

ocf_result_t rt_request_get_send(ocf_endpoint_s *endpoint, const char *uri_path, const char *query, bool receive_ack, request_callback callback);
ocf_result_t rt_request_put_send(ocf_endpoint_s *endpoint, const char *uri_path, const char *query, rt_rep_encoder_s *rep, bool receive_ack, request_callback callback);
ocf_result_t rt_request_post_send(ocf_endpoint_s *endpoint, const char *uri_path, const char *query, rt_rep_encoder_s *rep, bool receive_ack, request_callback callback);
ocf_result_t rt_request_delete_send(ocf_endpoint_s *endpoint, const char *uri_path, const char *query, rt_rep_encoder_s *rep, bool receive_ack, request_callback callback);
ocf_result_t rt_response_send(const rt_request_s *req, rt_rep_encoder_s *rep, ocf_response_result_t eh_result);
ocf_result_t rt_separate_accept(const rt_request_s *req, rt_request_s *separate_store);
ocf_result_t rt_response_resume(rt_request_s *separate_store, rt_rep_encoder_s *rep, ocf_response_result_t eh_result);

ocf_result_t rt_discovery(discovery_callback callback, const char *query);

#endif							/* RESOURCE_RT_REQUEST_H_ */
