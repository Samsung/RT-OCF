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

#ifndef __IOTIVITY_RT_RESOURCES_H
#define __IOTIVITY_RT_RESOURCES_H

#include "ocf_resources.h"
#include "rt_list.h"

typedef struct _rt_observe_s rt_observe_s;
typedef struct _rt_rep_encoder_s rt_rep_encoder_s;

typedef enum {
	RT_DISCOVERABLE = (1 << 0),
	RT_OBSERVABLE = (1 << 1),
} rt_resource_policy_t;

typedef struct _rt_resource_s {
	char *href;					//  TODO: how to merge it with the similar member at "coap_packet_t"
	size_t href_len;			//  TODO: how to merge it with the similar member at "coap_packet_t"
	uint8_t default_interface;
	uint8_t interfaces;
	rt_resource_type_list_s *resource_types;
	uint8_t p;
	// TODO : Duplicated variable
	bool is_secure;
	uint8_t scheme;
	rt_observe_s *observe_list;

	rt_list_s *links_list;

	ocf_request_cb get_handler;
	ocf_request_cb put_handler;
	ocf_request_cb post_handler;
	ocf_request_cb delete_handler;

	rt_node_s node;				// TODO: Please consider the right definition of rt_node_s
} rt_resource_s;

ocf_result_t rt_res_set_default_interface(rt_resource_s *resource, ocf_interface_mask_t);
ocf_result_t rt_res_get_default_interface(rt_resource_s *resource, uint8_t *interface);
ocf_result_t rt_res_is_interface_supported(rt_resource_s *resource, ocf_interface_mask_t);
ocf_result_t rt_res_set_interface(rt_resource_s *resource, ocf_interface_mask_t);
ocf_result_t rt_res_get_interface_string_value(uint8_t interface, char *interface_str);
ocf_interface_mask_t rt_res_get_interface_enum_value(char *interface_str);

ocf_result_t rt_res_set_resource_types(rt_resource_s *resource, const char **resource_types, uint8_t types_count);
ocf_result_t rt_res_is_resource_type_supported(rt_resource_s *resource, const char *resource_type);
ocf_result_t rt_res_resource_type_release(rt_resource_type_list_s *resource_types);

ocf_result_t rt_res_set_resource_protocol(rt_resource_s *resource, ocf_protocol_t scheme);
ocf_result_t rt_res_get_resource_protocol(rt_resource_s *resource, uint8_t *scheme);

rt_resource_s *rt_res_new_resource(const char *href);
void rt_res_delete_resource_components(rt_resource_s *resource);
void rt_res_delete_resource(rt_resource_s *resource);
void rt_res_set_request_handler(rt_resource_s *resource, ocf_method_t method, ocf_request_cb callback);

ocf_result_t rt_res_set_discoverable(rt_resource_s *resource, bool value);
ocf_result_t rt_res_set_observable(rt_resource_s *resource, bool value);
ocf_result_t rt_res_set_secure(rt_resource_s *resource, bool value);

ocf_result_t rt_res_add_if_rt_rep(rt_rep_encoder_s *main_map, rt_resource_s *resource);

#endif
