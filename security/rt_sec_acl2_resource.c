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

#include "rt_resources.h"
#include "rt_sec_persistent_storage.h"
#include "rt_sec_acl2_resource.h"
#include "rt_resources_manager.h"
#include "rt_utils.h"
#include "rt_logger.h"
#include "rt_rep.h"
#include "rt_sec_types.h"
#include "rt_mem.h"

#define TAG "RT_SEC_ACL2"

static rt_sec_acl2_s *g_sec_acl2 = NULL;
static rt_resource_s *g_acl2_resource = NULL;

static ocf_result_t get_rowner_id(rt_rep_decoder_s *rep, rt_sec_acl2_s *out, bool is_request);
static ocf_result_t get_num_of_element(rt_rep_decoder_s *array, uint16_t *num_of_element);
static ocf_result_t extract_subejct(rt_rep_decoder_s *acl2_map_item, rt_sec_ace_s *item);
static ocf_result_t extract_resources(rt_rep_decoder_s *acl2_map_item, rt_sec_ace_s *item);
static ocf_result_t extract_permission(rt_rep_decoder_s *acl2_map_item, rt_sec_ace_s *item);

static void get_handler_func(ocf_request_s request, ocf_rep_decoder_s data)
{
	RT_LOG_D(TAG, "%s : IN", __func__);
	rt_rep_encoder_s *rep = rt_convert_acl2_to_payload(g_sec_acl2, true);

	rt_response_send((rt_request_s *) request, rep, OCF_RESPONSE_CONTENT);
	rt_rep_encoder_release(rep);

	RT_LOG_D(TAG, "%s : OUT", __func__);
}

static ocf_result_t rt_sec_init_acl2_resource(void)
{
	RT_LOG_D(TAG, "%s : IN", __func__);

	if (g_acl2_resource != NULL) {
		RT_LOG_W(TAG, "acl2 already init");
		return OCF_ALREADY_INIT;
	}

	g_acl2_resource = rt_res_new_resource(OCF_ACL2_HREF);
	rt_res_set_discoverable(g_acl2_resource, true);
	rt_res_set_observable(g_acl2_resource, false);
	rt_res_set_interface(g_acl2_resource, OIC_IF_BASELINE);	
	const char *g_acl2_resource_types[1] = { OCF_ACL2_RT };
	rt_res_set_resource_types(g_acl2_resource, g_acl2_resource_types, 1);
	// TODO : Add put, post, delete handler
	rt_res_set_request_handler(g_acl2_resource, OCF_GET, get_handler_func);
	rt_res_set_secure(g_acl2_resource, true);

	// TODO : Should sync with device protocol
	rt_res_set_resource_protocol(g_acl2_resource, OCF_COAP | OCF_COAPS | OCF_COAP_TCP | OCF_COAPS_TCP);

	RT_LOG_D(TAG, "%s : OUT", __func__);

	return rt_res_register_resource(g_acl2_resource);
}

ocf_result_t rt_sec_acl2_init(void)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	if (g_sec_acl2 != NULL) {
		RT_LOG_W(TAG, "acl2 already init");
		return OCF_ALREADY_INIT;
	}

	rt_rep_decoder_s *rep = NULL;

	ocf_result_t ret = rt_sec_load_ps(RT_SEC_ACL2, &rep);
	if (OCF_OK != ret) {
		goto exit;
	}

	g_sec_acl2 = (rt_sec_acl2_s *) rt_mem_alloc(sizeof(rt_sec_acl2_s));
	RT_VERIFY_NON_NULL(g_sec_acl2, TAG, "g_sec_acl2");
	rt_list_init(&g_sec_acl2->aces, sizeof(rt_sec_ace_s), RT_MEMBER_OFFSET(rt_sec_ace_s, node));
	memset(g_sec_acl2->rowner_id, 0, RT_UUID_LEN);

	if (OCF_OK != rt_convert_payload_to_acl2(rep, g_sec_acl2, false)) {
		ret = OCF_ERROR;
		goto exit;
	}

	rt_sec_init_acl2_resource();

exit:
	if (rep) {
		rt_rep_decoder_release(rep);
		rep = NULL;
	}
	RT_LOG_D(TAG, "%s : OUT", __func__);

	return ret;
}

rt_rep_encoder_s *rt_convert_acl2_to_payload(rt_sec_acl2_s *acl2, bool is_response)
{
	RT_LOG_D(TAG, "%s : IN", __func__);
	RT_VERIFY_NON_NULL_RET(acl2, TAG, "acl2", NULL);

	rt_rep_encoder_s *rep = rt_rep_encoder_init(OCF_REP_MAP);
	rt_rep_encoder_s *acl2_array = rt_rep_encoder_init(OCF_REP_ARRAY);

	if (is_response) {
		rt_res_add_if_rt_rep(rep, g_acl2_resource);
	}

	rt_uuid_str_t uuid_str;
	uint8_t aceid = 1;
	rt_node_s *itr = acl2->aces.head;
	while (itr) {
		rt_rep_encoder_s *acl2_map = rt_rep_encoder_init(OCF_REP_MAP);

		rt_sec_ace_s *var = (rt_sec_ace_s *) rt_list_get_item(&acl2->aces, itr);

		// Set aceid
		rt_rep_add_int_to_map(acl2_map, OCF_ACL_ID, aceid++);

		// Set subject
		rt_rep_encoder_s *subject_map = rt_rep_encoder_init(OCF_REP_MAP);
		if (rt_sec_ace_uuid_subject == var->subject_type) {
			if (rt_uuid_is_astrict(var->subject_uuid)) {
				rt_rep_add_string_to_map(subject_map, OCF_ACL_UUID, OCF_WILDCARD_ALL);
			} else {
				rt_uuid_uuid2str(var->subject_uuid, uuid_str, RT_UUID_STR_LEN);
				rt_rep_add_string_to_map(subject_map, OCF_ACL_UUID, uuid_str);
			}
		} else {
			if (AUTH_CRYPT == var->subject_conn) {
				rt_rep_add_string_to_map(subject_map, OCF_ACL_CONNTYPE, OCF_ACL_AUTH_CRYPT);
			} else {
				rt_rep_add_string_to_map(subject_map, OCF_ACL_CONNTYPE, OCF_ACL_ANON_CLEAR);
			}
		}
		rt_rep_add_map_to_map(acl2_map, OCF_ACL_SUBJECT, subject_map);
		rt_rep_encoder_release(subject_map);

		// Set resources
		// array
		rt_rep_encoder_s *resources_array = rt_rep_encoder_init(OCF_REP_ARRAY);
		rt_sec_ace_resource_s *resource_itr = var->resources;
		int i;
		while (resource_itr) {
			rt_rep_encoder_s *resource_map = rt_rep_encoder_init(OCF_REP_MAP);

			// wc
			if (resource_itr->wc == RT_ALL_RESOURCES) {
				rt_rep_add_string_to_map(resource_map, OCF_ACL_WILDCARD_NAME, OCF_WILDCARD_ALL);
			} else if (resource_itr->wc == RT_ALL_NON_DISCOVERABLE) {
				rt_rep_add_string_to_map(resource_map, OCF_ACL_WILDCARD_NAME, OCF_ACL_WILDCARD_NON_DISCOVERIABLE);
			} else if (resource_itr->wc == RT_ALL_DISCOVERABLE) {
				rt_rep_add_string_to_map(resource_map, OCF_ACL_WILDCARD_NAME, OCF_ACL_WILDCARD_DISCOVERIABLE);
			}
			// href
			if (resource_itr->href) {
				rt_rep_add_string_to_map(resource_map, OCF_ACL_HREF, resource_itr->href);
			}
			// rt
			if (resource_itr->res_type_len > 0) {
				rt_rep_encoder_s *item_array = rt_rep_encoder_init(OCF_REP_ARRAY);
				for (i = 0; i < resource_itr->res_type_len; ++i) {
					rt_rep_add_string_to_array(item_array, resource_itr->res_type[i]);
				}
				rt_rep_add_array_to_map(resource_map, OIC_RT_NAME, item_array);
				rt_rep_encoder_release(item_array);
			}
			// if
			if (resource_itr->interface_len > 0) {
				rt_rep_encoder_s *item_array = rt_rep_encoder_init(OCF_REP_ARRAY);
				for (i = 0; i < resource_itr->interface_len; ++i) {
					rt_rep_add_string_to_array(item_array, resource_itr->interface[i]);
				}
				rt_rep_add_array_to_map(resource_map, OIC_IF_NAME, item_array);
				rt_rep_encoder_release(item_array);
			}

			rt_rep_add_map_to_array(resources_array, resource_map);
			rt_rep_encoder_release(resource_map);
			resource_itr = resource_itr->next;
		}
		rt_rep_add_array_to_map(acl2_map, OCF_ACL_RESOURCES, resources_array);
		rt_rep_encoder_release(resources_array);

		// Set permission
		rt_rep_add_int_to_map(acl2_map, OCF_ACL_PERMISSION, var->permission);

		// Add map
		rt_rep_add_map_to_array(acl2_array, acl2_map);
		rt_rep_encoder_release(acl2_map);

		itr = itr->next;
	}

	rt_rep_add_array_to_map(rep, OCF_ACL_LIST, acl2_array);
	rt_rep_encoder_release(acl2_array);

	// Set rowneruuid
	if (rt_uuid_is_empty(acl2->rowner_id) == false) {
		rt_uuid_uuid2str(acl2->rowner_id, uuid_str, RT_UUID_STR_LEN);
		rt_rep_add_string_to_map(rep, OCF_ROWNERUUID_NAME, uuid_str);
	}

	RT_LOG_D(TAG, "%s : OUT", __func__);
	return rep;
}

ocf_result_t rt_convert_payload_to_acl2(rt_rep_decoder_s *rep, rt_sec_acl2_s *out, bool is_request)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL(rep, TAG, "rep");
	RT_VERIFY_NON_NULL(out, TAG, "out");

	if (OCF_OK != get_rowner_id(rep, out, is_request)) {
		goto error;
	}

	rt_rep_decoder_s acl2_array;
	if (OCF_OK != rt_rep_get_array_from_map(rep, OCF_ACL_LIST, &acl2_array)) {
		goto error;
	}

	uint16_t num_of_element;
	if (OCF_OK != get_num_of_element(&acl2_array, &num_of_element)) {
		goto error;
	}

	int i;
	rt_rep_decoder_s acl2_map_item;
	rt_sec_ace_s *item = NULL;
	for (i = 0; i < num_of_element; i++) {
		if (OCF_OK != rt_rep_get_map_from_array(&acl2_array, i, &acl2_map_item)) {
			goto error;
		}

		item = (rt_sec_ace_s *) rt_mem_alloc(sizeof(rt_sec_ace_s));
		RT_VERIFY_NON_NULL_RET(item, TAG, "item", OCF_ERROR);

		if (OCF_OK != extract_subejct(&acl2_map_item, item)) {
			goto error_with_free;
		}

		if (OCF_OK != extract_resources(&acl2_map_item, item)) {
			goto error_with_free;
		}

		if (OCF_OK != extract_permission(&acl2_map_item, item)) {
			goto error_with_free;
		}

		rt_list_insert(&out->aces, &item->node);
	}

	RT_LOG_D(TAG, "%s OUT", __func__);
	return OCF_OK;

error_with_free:
	rt_mem_free(item);
error:
	RT_LOG_E(TAG, "%s FAIL", __func__);
	return OCF_ERROR;
}

static ocf_result_t get_rowner_id(rt_rep_decoder_s *rep, rt_sec_acl2_s *out, bool is_request)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	char rowner_id[RT_UUID_STR_LEN];
	ocf_result_t ret = OCF_OK;
	ret = rt_rep_get_string_from_map(rep, OCF_ROWNERUUID_NAME, rowner_id);
	if (OCF_OK != ret && !is_request) {
		RT_LOG_E(TAG, "%s OUT[FAIL]", __func__);
		return ret;
	} else if (OCF_OK == ret) {
		ret = rt_uuid_str2uuid(rowner_id, out->rowner_id);
		if (OCF_OK != ret) {
			RT_LOG_E(TAG, "%s OUT[FAIL]", __func__);
			return ret;
		}
	}
	RT_LOG_D(TAG, "%s OUT[OK]", __func__);
	return ret;
}

static ocf_result_t get_num_of_element(rt_rep_decoder_s *array, uint16_t *num_of_element)
{
	ocf_result_t ret = rt_rep_get_array_length(array, num_of_element);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "FAIL to get array length!");
		return OCF_ERROR;
	}
	return OCF_OK;
}

static ocf_result_t extract_subejct(rt_rep_decoder_s *acl2_map_item, rt_sec_ace_s *item)
{
	rt_rep_decoder_s sub_map;
	if (OCF_OK != rt_rep_get_map_from_map(acl2_map_item, OCF_ACL_SUBJECT, &sub_map)) {
		RT_LOG_E(TAG, "%s FAIL", __func__);
		return OCF_ERROR;
	}

	size_t len;
	ocf_result_t result_for_checking_subject_type = rt_rep_get_string_length_from_map(&sub_map, OCF_ACL_CONNTYPE, &len);
	if (result_for_checking_subject_type == OCF_OK) {

		char *conn_type = rt_mem_alloc(len);
		RT_VERIFY_NON_NULL_RET(conn_type, TAG, "conn_type", OCF_ERROR)

		if (OCF_OK != rt_rep_get_string_from_map(&sub_map, OCF_ACL_CONNTYPE, conn_type)) {
			RT_LOG_E(TAG, "%s FAIL", __func__);
			rt_mem_free(conn_type);
			return OCF_ERROR;
		}

		item->subject_type = rt_sec_ace_conntype_subject;

		if (0 == strcmp(conn_type, OCF_ACL_AUTH_CRYPT)) {
			item->subject_conn = AUTH_CRYPT;
		} else {
			item->subject_conn = ANON_CLEAR;
		}

		RT_LOG_D(TAG, "conn_type: %s", conn_type);
		rt_mem_free(conn_type);

	} else {
		if (OCF_OK != rt_rep_get_string_length_from_map(&sub_map, OCF_ACL_UUID, &len)) {
			RT_LOG_E(TAG, "%s FAIL", __func__);
			return OCF_ERROR;
		}

		if (OCF_WILDCARD_LEN == len) {
			memcpy(item->subject_uuid, OCF_WILDCARD_ALL, OCF_WILDCARD_LEN + 1);
		} else if (0 < len) {
			char *subject_uuid = rt_mem_alloc(len);
			RT_VERIFY_NON_NULL_RET(subject_uuid, TAG, "subject_uuid", OCF_ERROR)

			if (OCF_OK != rt_rep_get_string_from_map(&sub_map, OCF_ACL_UUID, subject_uuid)) {
				RT_LOG_E(TAG, "%s FAIL", __func__);
				rt_mem_free(subject_uuid);
				return OCF_ERROR;
			}

			item->subject_type = rt_sec_ace_uuid_subject;

			if (OCF_OK != rt_uuid_str2uuid(subject_uuid, item->subject_uuid)) {
				RT_LOG_E(TAG, "%s FAIL", __func__);
				rt_mem_free(subject_uuid);
				return OCF_ERROR;
			}

			RT_LOG_D(TAG, "subject_uuid: %s", subject_uuid);
			rt_mem_free(subject_uuid);
		}
	}

	return OCF_OK;
}

static ocf_result_t extract_resources(rt_rep_decoder_s *acl2_map_item, rt_sec_ace_s *item)
{
	rt_rep_decoder_s resources_array;
	rt_rep_get_array_from_map(acl2_map_item, OCF_ACL_RESOURCES, &resources_array);

	uint16_t num_of_resource = 0;
	if (OCF_OK != rt_rep_get_array_length(&resources_array, &num_of_resource)) {
		RT_LOG_E(TAG, "FAIL to get array length!");
		return OCF_ERROR;
	}

	rt_sec_ace_resource_s *prev = NULL;
	int index;
	for (index = 0; index < num_of_resource; index++) {
		rt_rep_decoder_s resource_map;
		if (OCF_OK != rt_rep_get_map_from_array(&resources_array, index, &resource_map)) {
			RT_LOG_E(TAG, "FAIL to get map from array!");
			return OCF_ERROR;
		}

		rt_sec_ace_resource_s *resource_item = rt_mem_alloc(sizeof(rt_sec_ace_resource_s));
		RT_VERIFY_NON_NULL_RET(resource_item, TAG, "resource_item alloc is failed", OCF_NO_MEMORY);
		resource_item->href = NULL;
		resource_item->res_type_len = 0;
		resource_item->interface_len = 0;
		resource_item->wc = RT_NO_WILDCARD;
		resource_item->next = NULL;
		RT_VERIFY_NON_NULL_RET(resource_item, TAG, "resource_item", OCF_ERROR);

		// wc
		size_t len;
		if (OCF_OK == rt_rep_get_string_length_from_map(&resource_map, OCF_ACL_WILDCARD_NAME, &len)) {
			char wc_temp[2];
			if (OCF_OK != rt_rep_get_string_from_map(&resource_map, OCF_ACL_WILDCARD_NAME, wc_temp)) {
				RT_LOG_E(TAG, "FAIL to get string from map!");
				return OCF_ERROR;
			}

			if (strcmp(wc_temp, OCF_WILDCARD_ALL) == 0) {
				resource_item->wc = RT_ALL_RESOURCES;
			} else if (strcmp(wc_temp, OCF_ACL_WILDCARD_DISCOVERIABLE) == 0) {
				resource_item->wc = RT_ALL_DISCOVERABLE;
			} else if (strcmp(wc_temp, OCF_ACL_WILDCARD_NON_DISCOVERIABLE) == 0) {
				resource_item->wc = RT_ALL_NON_DISCOVERABLE;
			} else {
				RT_LOG_E(TAG, "Invalid wildcard value");
				return OCF_ERROR;
			}
		}
		// href
		if (OCF_OK == rt_rep_get_string_length_from_map(&resource_map, OCF_ACL_HREF, &len)) {
			RT_LOG_D(TAG, "href_len: %d", (int)len);
			resource_item->href = rt_mem_alloc(len + 1);
			RT_VERIFY_NON_NULL_RET(resource_item->href, TAG, "resource_item->href alloc is failed", OCF_NO_MEMORY);
			if (OCF_OK != rt_rep_get_string_from_map(&resource_map, OCF_ACL_HREF, resource_item->href)) {
				RT_LOG_E(TAG, "FAIL to get string from map!");
				return OCF_ERROR;
			}
			RT_LOG_D(TAG, "href: %s", resource_item->href);
		}
		// rt
		int i;
		uint16_t num_of_item = 0;
		rt_rep_decoder_s item_array;
		if (OCF_OK == rt_rep_get_array_from_map(&resource_map, OIC_RT_NAME, &item_array)) {

			if (OCF_OK != rt_rep_get_array_length(&item_array, &num_of_item)) {
				RT_LOG_E(TAG, "Fail to get rt array length!");
				return OCF_ERROR;
			}

			RT_LOG_D(TAG, "num of rt: %d", (int)num_of_item);

			resource_item->res_type_len = num_of_item;
			resource_item->res_type = rt_mem_alloc(num_of_item);
			RT_VERIFY_NON_NULL_RET(resource_item->res_type, TAG, "resource_item->res_type alloc is failed", OCF_NO_MEMORY);
			for (i = 0; i < num_of_item; ++i) {
				if (OCF_OK != rt_rep_get_string_length_from_array(&item_array, i, &len)) {
					RT_LOG_E(TAG, "FAIL to get string length from array!");
					return OCF_ERROR;
				}
				resource_item->res_type[i] = rt_mem_alloc(len + 1);
				RT_VERIFY_NON_NULL_RET(resource_item->res_type[i], TAG, "resource_item->res_type[i] alloc is failed", OCF_NO_MEMORY);
				if (OCF_OK != rt_rep_get_string_from_array(&item_array, i, resource_item->res_type[i])) {
					RT_LOG_E(TAG, "FAIL to get string from rt array!");
					return OCF_ERROR;
				}
				RT_LOG_D(TAG, "res type[%d] : %s", i, resource_item->res_type[i]);
			}
		}
		// if
		if (OCF_OK == rt_rep_get_array_from_map(&resource_map, OIC_IF_NAME, &item_array)) {

			if (OCF_OK != rt_rep_get_array_length(&item_array, &num_of_item)) {
				RT_LOG_E(TAG, "Fail to get rt array length!");
				return OCF_ERROR;
			}

			RT_LOG_D(TAG, "num of if: %d", (int)num_of_item);

			resource_item->interface_len = num_of_item;
			resource_item->interface = rt_mem_alloc(num_of_item);
			RT_VERIFY_NON_NULL_RET(resource_item->interface, TAG, "resource_item->interface alloc is failed", OCF_NO_MEMORY);

			for (i = 0; i < num_of_item; ++i) {
				if (OCF_OK != rt_rep_get_string_length_from_array(&item_array, i, &len)) {
					RT_LOG_E(TAG, "FAIL to get string length from array!");
					return OCF_ERROR;
				}
				resource_item->interface[i] = rt_mem_alloc(len + 1);
				RT_VERIFY_NON_NULL_RET(resource_item->interface[i], TAG, "resource_item->interface[i] alloc is failed", OCF_NO_MEMORY);

				if (OCF_OK != rt_rep_get_string_from_array(&item_array, i, resource_item->interface[i])) {
					RT_LOG_E(TAG, "FAIL to get string from if array!");
					return OCF_ERROR;
				}
				RT_LOG_D(TAG, "interface[%d] : %s", i, resource_item->interface[i]);
			}
		}

		if (prev) {
			prev->next = resource_item;
		} else {
			item->resources = resource_item;
		}
		prev = resource_item;
	}
	return OCF_OK;
}

static ocf_result_t extract_permission(rt_rep_decoder_s *acl2_map_item, rt_sec_ace_s *item)
{
	int permission = 0;
	if (OCF_OK != rt_rep_get_int_from_map(acl2_map_item, OCF_ACL_PERMISSION, &permission)) {
		RT_LOG_E(TAG, "FAIL to get int from map");
		return OCF_ERROR;
	}
	item->permission = permission;
	RT_LOG_D(TAG, "permission: %d", permission);
	return OCF_OK;
}

static bool is_href_matched(rt_sec_ace_resource_s *resource_itr, const char *request_href)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	if (NULL == resource_itr->href || NULL == request_href) {
		RT_LOG_W(TAG, "href is Null");
		RT_LOG_D(TAG, "%s OUT", __func__);
		return false;
	}
	while (resource_itr && resource_itr->href) {
		if (0 == strcmp(resource_itr->href, request_href)) {
			RT_LOG_D(TAG, "Matched href exist");
			RT_LOG_D(TAG, "%s OUT", __func__);
			return true;
		}
		resource_itr = resource_itr->next;
	}
	RT_LOG_D(TAG, "%s OUT", __func__);
	return false;
}

static bool is_wildcard_matched(rt_sec_ace_resource_s *resource_itr, const char *request_href)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	if (RT_NO_WILDCARD == resource_itr->wc || NULL == request_href) {
		RT_LOG_W(TAG, "resourcs is Null");
		RT_LOG_D(TAG, "%s OUT", __func__);
		return false;
	}

	while (resource_itr && (RT_NO_WILDCARD < resource_itr->wc)) {
		if (resource_itr->wc == RT_ALL_RESOURCES) {
			RT_LOG_D(TAG, "Matches all resources");
			RT_LOG_D(TAG, "%s OUT", __func__);
			return true;
		} else if (resource_itr->wc == RT_ALL_DISCOVERABLE) {
			if (true == rt_res_is_discoverable_by_href(request_href)) {
				RT_LOG_D(TAG, "Matches all discoverable resources");
				RT_LOG_D(TAG, "%s OUT", __func__);
				return true;
			}
		} else if (resource_itr->wc == RT_ALL_NON_DISCOVERABLE) {
			if (false == rt_res_is_discoverable_by_href(request_href)) {
				RT_LOG_D(TAG, "Matches all non-discoverable resources");
				RT_LOG_D(TAG, "%s OUT", __func__);
				return true;
			}
		}
		resource_itr = resource_itr->next;
	}
	RT_LOG_D(TAG, "%s OUT", __func__);
	return false;
}

bool rt_sec_acl2_check_permission_by_subjectuuid(rt_uuid_t subject, const char *request_href, uint16_t perm)
{
	RT_VERIFY_NON_NULL_RET(g_sec_acl2, TAG, "g_sec_acl2 is NULL", false);
	RT_LOG_D(TAG, "%s IN", __func__);
	rt_node_s *itr = g_sec_acl2->aces.head;
	while (itr) {
		rt_sec_ace_s *var = (rt_sec_ace_s *) rt_list_get_item(&g_sec_acl2->aces, itr);
		itr = itr->next;
		if (rt_sec_ace_uuid_subject == var->subject_type) {
			// check to match subjectuuid or wildcard
			if ((0 == memcmp(subject, var->subject_uuid, RT_UUID_LEN)) || rt_uuid_is_astrict(var->subject_uuid)) {
				// check to match href and permission
				if (true == is_href_matched(var->resources, request_href) && (perm & var->permission)) {
					RT_LOG_D(TAG, "%s OUT", __func__);
					return true;
				} else if (true == is_wildcard_matched(var->resources, request_href) && (perm & var->permission)) {
					RT_LOG_D(TAG, "%s OUT", __func__);
					return true;
				}
			}
		}
	}

	RT_LOG_D(TAG, "%s OUT", __func__);
	return false;
}

bool rt_sec_acl2_check_permission_by_conntype(rt_sec_conn_type_t conntype, const char *request_href, uint16_t perm)
{
	RT_VERIFY_NON_NULL_RET(g_sec_acl2, TAG, "g_sec_acl2 is NULL", false);
	RT_LOG_D(TAG, "%s IN", __func__);
	rt_node_s *itr = g_sec_acl2->aces.head;
	while (itr) {
		rt_sec_ace_s *var = (rt_sec_ace_s *) rt_list_get_item(&g_sec_acl2->aces, itr);
		itr = itr->next;
		if (rt_sec_ace_conntype_subject == var->subject_type) {
			// check to match conntype
			if (conntype == var->subject_conn) {
				// check to match href and permission
				if (true == is_href_matched(var->resources, request_href) && (perm & var->permission)) {
					RT_LOG_D(TAG, "%s OUT", __func__);
					return true;
				} else if (true == is_wildcard_matched(var->resources, request_href) && (perm & var->permission)) {
					RT_LOG_D(TAG, "%s OUT", __func__);
					return true;
				}				
			}
		}
	}
	RT_LOG_D(TAG, "%s OUT", __func__);
	return false;
}

ocf_result_t rt_sec_acl2_terminate(void)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	if (NULL == g_sec_acl2) {
		RT_LOG_W(TAG, "acl2 resource is not initialized");
		return OCF_ERROR;
	}

	rt_node_s *itr;
	itr = g_sec_acl2->aces.head;
	while (itr) {
		rt_sec_ace_s *var;
		var = (rt_sec_ace_s *) rt_list_get_item(&g_sec_acl2->aces, itr);
		rt_sec_ace_resource_s *current = var->resources;
		while (current) {
			int i;
			rt_mem_free(current->href);

			for (i = 0; i < current->res_type_len; ++i) {
				rt_mem_free(current->res_type[i]);
			}
			rt_mem_free(current->res_type);

			for (i = 0; i < current->interface_len; ++i) {
				rt_mem_free(current->interface[i]);
			}
			rt_mem_free(current->interface);

			rt_sec_ace_resource_s *prev = current;
			current = current->next;
			rt_mem_free(prev);
		}
		itr = itr->next;
	}
	rt_list_terminate(&g_sec_acl2->aces, NULL);
	rt_mem_free(g_sec_acl2);
	g_sec_acl2 = NULL;
	g_acl2_resource = NULL;
	RT_LOG_D(TAG, "%s OUT", __func__);
	return OCF_OK;
}
