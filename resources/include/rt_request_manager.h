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

#ifndef RESOURCE_RT_REQUEST_MANAGER_H_
#define RESOURCE_RT_REQUEST_MANAGER_H_

#include "ocf_types.h"

typedef enum {
	REQUEST = 0,
	OBSERVE,
	DISCOVERY,
} request_type_t;

typedef struct _rt_data_s rt_data_s;

ocf_result_t rt_request_manager_init(void);
ocf_result_t rt_request_manager_terminate(void);

ocf_result_t rt_send_coap_payload(rt_data_s *send_data, const ocf_endpoint_s *endpoint);

ocf_result_t rt_request_make_request_callback_item(request_type_t type, ocf_version_t version, void *callback, rt_token_s *token);
ocf_result_t rt_request_callback_item_release_with_token(rt_token_s token);

#endif							/* RESOURCE_RT_REQUEST_MANAGER_H_ */
