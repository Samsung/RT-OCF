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

#include "rt_remote_resource.h"
#include "rt_resources.h"
#include "rt_rep.h"
#include "rt_url.h"
#include "rt_utils.h"
#include "rt_logger.h"
#include "rt_timer.h"

#define TAG "RT_REMOTE_RESOURCE"

static int rt_atoi(const char *string)
{
	int result = 0;
	unsigned int digit;
	int sign;

	/*
	 * Check for a sign.
	 */
	if (*string == '-') {
		sign = 1;
		string += 1;
	} else {
		sign = 0;
		if (*string == '+') {
			string += 1;
		}
	}

	for (;; string += 1) {
		digit = *string - '0';
		if (digit > 9) {
			break;
		}
		result = (10 * result) + digit;
	}

	if (sign) {
		return -result;
	}
	return result;
}

static ocf_result_t rt_parse_common_discovery_response(rt_rep_decoder_s res_rep, ocf_remote_resource_s *current_resource)
{
	rt_rep_get_string_length_from_map(&res_rep, "href", &current_resource->href_len);
	current_resource->href = rt_mem_alloc(current_resource->href_len);
	if (current_resource->href == NULL) {
		return OCF_ERROR;
	}
	rt_rep_get_string_from_map(&res_rep, "href", current_resource->href);

	rt_rep_decoder_s rt_array;
	rt_rep_get_array_from_map(&res_rep, "rt", &rt_array);
	uint16_t rt_array_len = 0;
	rt_rep_get_array_length(&rt_array, &rt_array_len);

	current_resource->resource_types = NULL;
	int j = 0;
	for (j = 0; j < rt_array_len; j++) {
		char resource_type_buffer[MAX_RESOURCE_TYPE_STRING_LENGTH];
		rt_rep_get_string_from_array(&rt_array, j, resource_type_buffer);
		int buffer_len = strlen(resource_type_buffer);

		rt_resource_type_list_s *current_resource_type = (rt_resource_type_list_s *) rt_mem_alloc(sizeof(rt_resource_type_list_s));
		if (current_resource_type == NULL) {
			RT_LOG_E(TAG, "alloc failed at %s!!", __func__);
			return OCF_ERROR;
		}
		current_resource_type->resource_type = (char *)rt_mem_alloc(sizeof(char) * (buffer_len + 1));
		if (current_resource_type->resource_type == NULL) {
			rt_mem_free(current_resource_type);
			RT_LOG_E(TAG, "alloc failed at %s!!", __func__);
			return OCF_ERROR;
		}
		rt_strncpy(current_resource_type->resource_type, resource_type_buffer, buffer_len);

		current_resource_type->next = current_resource->resource_types;
		current_resource->resource_types = current_resource_type;
	}

	rt_rep_decoder_s if_array;
	rt_rep_get_array_from_map(&res_rep, "if", &if_array);
	uint16_t if_array_len = 0;
	rt_rep_get_array_length(&if_array, &if_array_len);

	current_resource->interfaces = 0;
	int k;
	for (k = 0; k < if_array_len; k++) {
		char interface_buffer[16];
		rt_rep_get_string_from_array(&if_array, k, interface_buffer);
		current_resource->interfaces |= rt_res_get_interface_enum_value(interface_buffer);
	}

	rt_rep_decoder_s p_map;
	if (rt_rep_get_map_from_map(&res_rep, "p", &p_map) == OCF_OK) {
		int p = 0;
		rt_rep_get_int_from_map(&p_map, "bm", &p);
		current_resource->p = p;
	}
	return OCF_OK;
}

ocf_remote_resource_s *parse_discovery_payload_oic_1_1(rt_rep_decoder_s *rep)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	ocf_remote_resource_s *remote_resources = NULL;
	rt_rep_decoder_s root_map;
	uint16_t root_array_size = 0;

	rt_rep_get_array_length(rep, &root_array_size);
	if (root_array_size != 1) {
		RT_LOG_E(TAG, "invalid payload");
		return NULL;
	}
	rt_rep_get_map_from_array(rep, 0, &root_map);

	rt_rep_decoder_s links_array;
	if (rt_rep_get_array_from_map(&root_map, "links", &links_array) != OCF_OK) {
		goto clean_to_fail;
	}

	uint16_t len = 0;
	rt_rep_get_array_length(&links_array, &len);

	int i = 0;
	for (i = 0; i < len; i++) {
		rt_rep_decoder_s res_map;
		rt_rep_get_map_from_array(&links_array, i, &res_map);

		ocf_remote_resource_s *current_resource = rt_mem_alloc(sizeof(ocf_remote_resource_s));
		if (current_resource == NULL || (rt_parse_common_discovery_response(res_map, current_resource) == OCF_ERROR)) {
			goto clean_to_fail;
		}

		current_resource->next = remote_resources;
		remote_resources = current_resource;
	}
	RT_LOG_D(TAG, "%s OUT", __func__);

	return remote_resources;

clean_to_fail:
	if (remote_resources) {
		rt_remote_resource_release_all_item(remote_resources);
	}
	return NULL;

}

ocf_remote_resource_s *parse_discovery_payload_ocf_1_0(rt_rep_decoder_s *rep)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	uint16_t root_array_size = 0;
	rt_rep_get_array_length(rep, &root_array_size);
	int i, k;
	ocf_remote_resource_s *remote_resources = NULL;
	for (i = 0; i < root_array_size; i++) {
		rt_rep_decoder_s res_map;
		rt_rep_get_map_from_array(rep, i, &res_map);
		ocf_remote_resource_s *current_resource = rt_mem_alloc(sizeof(ocf_remote_resource_s));
		if (current_resource == NULL || (rt_parse_common_discovery_response(res_map, current_resource) == OCF_ERROR)) {
			RT_LOG_E(TAG, "alloc failed at %s!!", __func__);
			goto clean_to_fail;
		}

		rt_rep_decoder_s endpoint_array;
		rt_rep_get_array_from_map(&res_map, "eps", &endpoint_array);
		uint16_t ep_array_len = 0;
		rt_rep_get_array_length(&endpoint_array, &ep_array_len);

		for (k = 0; k < ep_array_len; k++) {
			rt_rep_decoder_s ep_map;
			rt_rep_get_map_from_array(&endpoint_array, k, &ep_map);
			char url[MAX_ENDPOINT_URL_LENGTH];
			rt_rep_get_string_from_map(&ep_map, "ep", url);
			rt_url_field_s *parsed_ep = rt_url_parse(url);
			ocf_endpoint_list_s *current_endpoint = (ocf_endpoint_list_s *) rt_mem_alloc(sizeof(ocf_endpoint_list_s));
			if (current_endpoint == NULL) {
				RT_LOG_E(TAG, "alloc failed at %s!!", __func__);
				rt_url_free(parsed_ep);
				goto clean_to_fail;
			}
			ocf_transport_flags_t flags = 0;
			if (OCF_OK != rt_endpoint_get_flags(parsed_ep, &flags)) {
				RT_LOG_E(TAG, "rt_endpoint_get_flags in %s!!", __func__);
				rt_url_free(parsed_ep);
				goto clean_to_fail;
			}
			rt_endpoint_set(&current_endpoint->endpoint, parsed_ep->host, rt_atoi(parsed_ep->port), flags);
			rt_url_free(parsed_ep);
			current_endpoint->next = current_resource->endpoint_list;
			current_resource->endpoint_list = current_endpoint;
		}

		current_resource->next = remote_resources;
		remote_resources = current_resource;
	}
	RT_LOG_D(TAG, "%s OUT", __func__);

	return remote_resources;

clean_to_fail:
	rt_remote_resource_release_all_item(remote_resources);
	return NULL;
}

static void remove_endpoint_list(ocf_endpoint_list_s *endpoint_list)
{
	ocf_endpoint_list_s *cur_endpoint = endpoint_list;
	while (cur_endpoint) {
		ocf_endpoint_list_s *temp = cur_endpoint;
		RT_VERIFY_NON_NULL_VOID(temp, TAG, "temp");

		cur_endpoint = cur_endpoint->next;
		rt_mem_free(temp);
	}
}

static void rt_remote_resource_release_item(ocf_remote_resource_s *cur_resource)
{
	RT_VERIFY_NON_NULL_VOID(cur_resource, TAG, "cur_resource");

	if (cur_resource->href) {
		rt_mem_free(cur_resource->href);
		cur_resource->href = NULL;
	}

	if (cur_resource->resource_types) {
		rt_res_resource_type_release(cur_resource->resource_types);
		cur_resource->resource_types = NULL;
	}

	if (cur_resource->endpoint_list) {
		remove_endpoint_list(cur_resource->endpoint_list);
		cur_resource->endpoint_list = NULL;
	}

	rt_mem_free(cur_resource);
}

void rt_remote_resource_release_all_item(ocf_remote_resource_s *remote_resource)
{
	ocf_remote_resource_s *cur_resource = remote_resource;
	while (cur_resource) {
		ocf_remote_resource_s *temp = cur_resource;
		cur_resource = cur_resource->next;
		rt_remote_resource_release_item(temp);
		temp = NULL;
	}
}
