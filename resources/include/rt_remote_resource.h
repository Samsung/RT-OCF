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

#ifndef RESOURCE_RT_REMOTE_RESOURCE_H_
#define RESOURCE_RT_REMOTE_RESOURCE_H_

#include "ocf_types.h"

#define MAX_RESOURCE_TYPE_STRING_LENGTH 64
#define MAX_ENDPOINT_URL_LENGTH 256

typedef struct _rt_resource_type_list_s rt_resource_type_list_s;
typedef struct _rt_rep_decoder_s rt_rep_decoder_s;

typedef struct _ocf_endpoint_list_s {
	ocf_endpoint_s endpoint;
	struct _ocf_endpoint_list_s *next;
} ocf_endpoint_list_s;

typedef struct _ocf_remote_resource_s {
	char *href;
	size_t href_len;
	uint8_t interfaces;
	rt_resource_type_list_s *resource_types;
	uint8_t p;
	ocf_endpoint_list_s *endpoint_list;
	struct _ocf_remote_resource_s *next;
} ocf_remote_resource_s;


ocf_remote_resource_s *parse_discovery_payload_oic_1_1(rt_rep_decoder_s *rep);
ocf_remote_resource_s *parse_discovery_payload_ocf_1_0(rt_rep_decoder_s *rep);
void rt_remote_resource_release_all_item(ocf_remote_resource_s *remote_resource);

#endif							/* RESOURCE_RT_REMOTE_RESOURCE_H_ */
