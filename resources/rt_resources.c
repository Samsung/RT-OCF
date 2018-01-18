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

#include <string.h>
#include "rt_resources.h"
#include "rt_rep.h"
#include "rt_mem.h"
#include "rt_utils.h"
#include "rt_list.h"
#include "rt_receive_queue.h"
#include "rt_string.h"

#define TAG "RT_RESOURCES"

rt_resource_s *rt_res_new_resource(const char *href)
{
	RT_VERIFY_NON_NULL_RET(href, TAG, "href is NULL", NULL);

	size_t len = strlen(href);

	RT_VERIFY_NON_ZERO_RET(len, TAG, "len of href is zero", NULL);

	if (rt_res_get_resource_by_href(href)) {
		return NULL;
	}
	// TODO: check the range of num_resource_types;
	// TODO: check the range of device;

	rt_resource_s *res = rt_mem_alloc(sizeof(rt_resource_s));
	RT_VERIFY_NON_NULL_RET(res, TAG, "res alloc is failed", NULL);
	memset(res, 0, sizeof(rt_resource_s));

	res->href = rt_mem_alloc(sizeof(char) * (len + 1));
	if (!(res->href)) {
		rt_mem_free(res);
		RT_VERIFY_NON_NULL_RET(NULL, TAG, "href alloc is failed", NULL);
	}

	rt_strncpy(res->href, href, len);

	res->scheme = OCF_COAP;
	res->href_len = len;
	res->interfaces = OIC_IF_BASELINE;

	res->resource_types = NULL;
	res->observe_list = NULL;
	res->links_list = NULL;

	return res;
}

void rt_res_delete_resource(rt_resource_s *resource)
{
	rt_res_delete_resource_components(resource);
	rt_mem_free(resource);
	resource = NULL;
}

void rt_res_delete_resource_components(rt_resource_s *resource)
{
	RT_VERIFY_NON_NULL_VOID(resource, TAG, "resource");

	if (resource->href) {
		rt_mem_free(resource->href);
	}

	if (resource->links_list) {
		rt_res_remove_links(resource);
	}

	release_observe_list(resource->observe_list);
	rt_res_resource_type_release(resource->resource_types);
	resource->href_len = 0;
}

void rt_res_set_request_handler(rt_resource_s *resource, ocf_method_t method, ocf_request_cb callback)
{
	RT_VERIFY_NON_NULL_VOID(resource, TAG, "resource is NULL");

	switch (method) {
	case OCF_GET:
		resource->get_handler = callback;
		break;
	case OCF_POST:
		resource->post_handler = callback;
		break;
	case OCF_PUT:
		resource->put_handler = callback;
		break;
	case OCF_DELETE:
		resource->delete_handler = callback;
		break;
	default:
		RT_LOG_E(TAG, "unknown method : 0x%x ", method);
	}

	return;
}

ocf_result_t rt_res_set_discoverable(rt_resource_s *resource, bool value)
{
	RT_VERIFY_NON_NULL_RET(resource, TAG, "resource is NULL", OCF_RESOURCE_ERROR);
	if (value) {
		resource->p |= RT_DISCOVERABLE;
	} else {
		resource->p &= ~RT_DISCOVERABLE;
	}
	return OCF_OK;
}

ocf_result_t rt_res_set_observable(rt_resource_s *resource, bool value)
{
	RT_VERIFY_NON_NULL_RET(resource, TAG, "resource is NULL", OCF_RESOURCE_ERROR);
	if (value) {
		resource->p |= RT_OBSERVABLE;
	} else {
		resource->p &= ~RT_OBSERVABLE;
	}
	return OCF_OK;
}

ocf_result_t rt_res_set_secure(rt_resource_s *resource, bool value)
{
	RT_VERIFY_NON_NULL_RET(resource, TAG, "resource is NULL", OCF_RESOURCE_ERROR);
	resource->is_secure = value;
	return OCF_OK;
}

ocf_result_t rt_res_set_default_interface(rt_resource_s *resource, ocf_interface_mask_t interface)
{
	RT_VERIFY_NON_NULL_RET(resource, TAG, "resource is NULL", OCF_RESOURCE_ERROR);
	resource->default_interface = interface;
	resource->interfaces |= interface;
	return OCF_OK;
}

ocf_result_t rt_res_get_default_interface(rt_resource_s *resource, uint8_t *interface)
{
	RT_VERIFY_NON_NULL_RET(resource, TAG, "resource is NULL", OCF_RESOURCE_ERROR);
	*interface = resource->default_interface;
	return OCF_OK;
}

ocf_result_t rt_res_is_interface_supported(rt_resource_s *resource, ocf_interface_mask_t interface)
{
	RT_VERIFY_NON_NULL_RET(resource, TAG, "resource is NULL", OCF_RESOURCE_ERROR);
	if (resource->interfaces & interface) {
		return OCF_OK;
	}
	return OCF_ERROR;
}

ocf_result_t rt_res_set_resource_protocol(rt_resource_s *resource, ocf_protocol_t scheme)
{
	RT_VERIFY_NON_NULL_RET(resource, TAG, "resource is NULL", OCF_RESOURCE_ERROR);
	resource->scheme = scheme;
	return OCF_OK;
}

ocf_result_t rt_res_get_resource_protocol(rt_resource_s *resource, uint8_t *scheme)
{
	RT_VERIFY_NON_NULL_RET(resource, TAG, "resource is NULL", OCF_RESOURCE_ERROR);
	*scheme = resource->scheme;
	return OCF_OK;
}

ocf_result_t rt_res_set_interface(rt_resource_s *resource, ocf_interface_mask_t interface)
{
	RT_VERIFY_NON_NULL_RET(resource, TAG, "resource is NULL", OCF_RESOURCE_ERROR);
	resource->interfaces |= interface;
	return OCF_OK;
}

ocf_result_t rt_res_get_interface_string_value(uint8_t interface, char *interface_str)
{

	char *str_ret = NULL;

	switch (interface) {
	case OIC_IF_BASELINE:
		str_ret = rt_strcpy(interface_str, OIC_IF_BASELINE_VALUE);
		break;
	case OIC_IF_LL:
		str_ret = rt_strcpy(interface_str, OIC_IF_LL_VALUE);
		break;
	case OIC_IF_B:
		str_ret = rt_strcpy(interface_str, OIC_IF_B_VALUE);
		break;
	case OIC_IF_R:
		str_ret = rt_strcpy(interface_str, OIC_IF_R_VALUE);
		break;
	case OIC_IF_RW:
		str_ret = rt_strcpy(interface_str, OIC_IF_RW_VALUE);
		break;
	case OIC_IF_A:
		str_ret = rt_strcpy(interface_str, OIC_IF_A_VALUE);
		break;
	case OIC_IF_S:
		str_ret = rt_strcpy(interface_str, OIC_IF_S_VALUE);
		break;
	default:
		return OCF_INVALID_PARAM;
	}

	RT_VERIFY_NON_NULL_RET(str_ret, TAG, "get_interface_string is failed", OCF_INVALID_PARAM);
	return OCF_OK;
}

ocf_interface_mask_t rt_res_get_interface_enum_value(char *interface_str)
{
	if (strncmp(OIC_IF_BASELINE_VALUE, interface_str, strlen(interface_str)) == 0) {
		return OIC_IF_BASELINE;
	} else if (strncmp(OIC_IF_LL_VALUE, interface_str, strlen(interface_str)) == 0) {
		return OIC_IF_LL;
	} else if (strncmp(OIC_IF_B_VALUE, interface_str, strlen(interface_str)) == 0) {
		return OIC_IF_B;
	} else if (strncmp(OIC_IF_R_VALUE, interface_str, strlen(interface_str)) == 0) {
		return OIC_IF_R;
	} else if (strncmp(OIC_IF_RW_VALUE, interface_str, strlen(interface_str)) == 0) {
		return OIC_IF_RW;
	} else if (strncmp(OIC_IF_A_VALUE, interface_str, strlen(interface_str)) == 0) {
		return OIC_IF_A;
	} else if (strncmp(OIC_IF_S_VALUE, interface_str, strlen(interface_str)) == 0) {
		return OIC_IF_S;
	}

	RT_LOG_E(TAG, "Invalid interface string %s", interface_str);
	return OIC_IF_INVALID;
}

ocf_result_t rt_res_set_resource_types(rt_resource_s *resource, const char **resource_types, uint8_t types_count)
{
	RT_VERIFY_NON_NULL_RET(resource, TAG, "resource is NULL", OCF_RESOURCE_ERROR);

	int i;
	for (i = 0; i < types_count; ++i) {
		rt_resource_type_list_s *node = (rt_resource_type_list_s *) rt_mem_alloc(sizeof(rt_resource_type_list_s));
		RT_VERIFY_NON_NULL_RET(node, TAG, "node is null", OCF_MEM_FULL);
		node->resource_type = (char *)rt_mem_dup(resource_types[i], sizeof(char) * (strlen(resource_types[i]) + 1));
		node->next = resource->resource_types;
		resource->resource_types = node;
	}

	return OCF_OK;
}

ocf_result_t rt_res_is_resource_type_supported(rt_resource_s *resource, const char *resource_type)
{
	RT_VERIFY_NON_NULL_RET(resource, TAG, "resource", OCF_RESOURCE_ERROR);
	RT_VERIFY_NON_NULL_RET(resource_type, TAG, NULL, OCF_OK);

	rt_resource_type_list_s *node = resource->resource_types;
	while (node) {
		if (!strcmp(node->resource_type, resource_type)) {
			return OCF_OK;
		}
		node = node->next;
	}
	return OCF_ERROR;
}

ocf_result_t rt_res_resource_type_release(rt_resource_type_list_s *resource_types)
{
	RT_VERIFY_NON_NULL_RET(resource_types, TAG, "resource_types", OCF_INVALID_PARAM);

	rt_resource_type_list_s *node = resource_types;
	rt_resource_type_list_s *temp = NULL;
	while (node) {
		temp = node;
		node = temp->next;
		if (temp->resource_type) {
			rt_mem_free(temp->resource_type);
		}
		rt_mem_free(temp);
	}
	return OCF_OK;
}

static rt_rep_encoder_s *rt_get_rt_representation(rt_resource_s *resource)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL_RET(resource, TAG, "resource is NULL", NULL);

	if (!resource->resource_types) {
		RT_LOG_W(TAG, "%s resource don't have any resource type.", resource->href);
		return NULL;
	}

	rt_rep_encoder_s *rt_array = rt_rep_encoder_init(OCF_REP_ARRAY);
	rt_resource_type_list_s *resource_type_node = resource->resource_types;
	while (resource_type_node != NULL) {
		rt_rep_add_string_to_array(rt_array, resource_type_node->resource_type);
		resource_type_node = resource_type_node->next;
	}
	RT_LOG_D(TAG, "%s OUT", __func__);
	return rt_array;
}

static rt_rep_encoder_s *rt_get_if_representation(rt_resource_s *resource)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL_RET(resource, TAG, "resource is NULL", NULL);
	uint8_t interface = 1;
	rt_rep_encoder_s *if_array = rt_rep_encoder_init(OCF_REP_ARRAY);
	do {
		if (resource->interfaces & interface) {
			char interface_str[20];
			rt_res_get_interface_string_value(interface, interface_str);
			rt_rep_add_string_to_array(if_array, interface_str);
		}
	} while ((interface <<= 1) <= (1 << 6));
	RT_LOG_D(TAG, "%s OUT", __func__);
	return if_array;
}

ocf_result_t rt_res_add_if_rt_rep(rt_rep_encoder_s *main_map, rt_resource_s *resource)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL_RET(main_map, TAG, "main_map is NULL", OCF_INVALID_PARAM);
	RT_VERIFY_NON_NULL_RET(resource, TAG, "resource is NULL", OCF_INVALID_PARAM);
	ocf_result_t result = OCF_ERROR;
	rt_rep_encoder_s *rt_array = NULL;
	rt_rep_encoder_s *if_array = NULL;

	rt_array = rt_get_rt_representation(resource);
	if (rt_array) {
		result = rt_rep_add_array_to_map(main_map, OIC_RT_NAME, rt_array);
		if (OCF_OK != result) {
			RT_LOG_E(TAG, "Fail to rt_get_rt_representation");
			goto exit;
		}
	}

	if_array = rt_get_if_representation(resource);
	if (if_array) {
		result = rt_rep_add_array_to_map(main_map, OIC_IF_NAME, if_array);
		if (OCF_OK != result) {
			RT_LOG_E(TAG, "Fail to rt_get_if_representation");
			goto exit;
		}
	}

exit:
	if (NULL != rt_array) {
		rt_rep_encoder_release(rt_array);
	}
	if (NULL != if_array) {
		rt_rep_encoder_release(if_array);
	}
	RT_LOG_D(TAG, "%s OUT", __func__);
	return result;
}
