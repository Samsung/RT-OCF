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

#ifndef OCFREQUEST_H_
#define OCFREQUEST_H_

#include "ocf_types.h"
#include "ocf_rep.h"
#include "rt_remote_resource.h" //TODO : when wrapping remoter_reosurce, it should removed.

#ifdef __cplusplus
extern "C" {
#endif							// __cplusplus

typedef struct rt_request_s *ocf_request_s;

typedef void (*discovery_callback)(ocf_remote_resource_s *remote_resources, ocf_response_result_t code);
typedef void (*request_callback)(ocf_rep_decoder_s rep, ocf_response_result_t code);

ocf_request_query_set_s *ocf_request_get_queries(ocf_request_s request);

ocf_result_t ocf_request_get_send(ocf_endpoint_s *endpoint, const char *uri_path, const char *query, bool receive_ack, request_callback callback);
ocf_result_t ocf_request_put_send(ocf_endpoint_s *endpoint, const char *uri_path, const char *query, ocf_rep_encoder_s rep, bool receive_ack, request_callback callback);
ocf_result_t ocf_request_post_send(ocf_endpoint_s *endpoint, const char *uri_path, const char *query, ocf_rep_encoder_s rep, bool receive_ack, request_callback callback);
ocf_result_t ocf_request_delete_send(ocf_endpoint_s *endpoint, const char *uri_path, const char *query, ocf_rep_encoder_s rep, bool receive_ack, request_callback callback);
ocf_result_t ocf_response_send(const ocf_request_s req, ocf_rep_encoder_s rep, ocf_response_result_t eh_result);

ocf_result_t ocf_discovery(discovery_callback callback, const char *query);

#ifdef __cplusplus
}
#endif							// __cplusplus
#endif
