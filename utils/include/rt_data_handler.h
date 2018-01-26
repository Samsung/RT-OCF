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

#ifndef __RT_OCF_DATA_HANDLER_H
#define __RT_OCF_DATA_HANDLER_H

#include "ocf_types.h"
#include "rt_coap_constants.h"

typedef enum {
	OBSERVE_REGISTER = 0,
	OBSERVE_DEREGISTER,
	OBSERVE_NONE
} rt_observe_type_t;

typedef enum {
	RT_OPTION_TRANSACTION_REQUEST = 1 << 0,
	RT_OPTION_TRANSACTION_RESPONSE = 1 << 1,
	RT_OPTION_OBSERVE = 1 << 2,
	RT_OPTION_BLOCK = 1 << 3
} rt_data_flag_t;

typedef struct _rt_data_s {
	rt_data_flag_t flags;
	coap_message_type_t type;
	uint8_t code;
	uint32_t observe_num;
	ocf_version_t accept;
	ocf_version_t content_format;
	uint16_t mid;
	rt_token_s token;
	const char *uri_path;
	const char *query;
	uint8_t *payload;
	uint32_t payload_len;
} rt_data_s;

ocf_result_t rt_data_clone(rt_data_s *dst, const rt_data_s *src);
rt_data_s *rt_receive_data_make_item_without_payload(void *coap_data);
rt_data_s *rt_receive_data_make_item(void *coap_data);
ocf_result_t rt_data_free_item(rt_data_s *data);

#endif
