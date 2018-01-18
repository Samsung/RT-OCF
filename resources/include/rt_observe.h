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

#ifndef RESOURCE_RT_OBSERVE_H_
#define RESOURCE_RT_OBSERVE_H_

#include "ocf_observe.h"

typedef struct _rt_observe_s {
	char *href;
	uint32_t seq_num;
	rt_token_s token;
	ocf_endpoint_s endpoint;
	ocf_message_type_t msg_type;
	ocf_version_t accept;
	struct _rt_observe_s *next;
} rt_observe_s;

//Forward Declarations.
typedef struct _rt_resource_s rt_resource_s;
typedef struct _rt_data_s rt_data_s;
typedef struct _rt_rep_encoder_s rt_rep_encoder_s;

ocf_result_t rt_observe_init(void);
void rt_observe_terminate(void);

ocf_result_t rt_observe_register(const ocf_endpoint_s *endpoint, const char *uri_path, observe_callback callback);
ocf_result_t rt_observe_deregister(const ocf_endpoint_s *endpoint, const char *uri_path);

ocf_result_t rt_observe_notify(const char *href, rt_rep_encoder_s *rep);

void release_observe_list(rt_observe_s *observe_list);
ocf_result_t rt_observe_handle_observe_request(rt_resource_s *resource, const rt_data_s *packet, const ocf_endpoint_s *endpoint);

#endif							/* RESOURCE_RT_OBSERVE_H_ */
