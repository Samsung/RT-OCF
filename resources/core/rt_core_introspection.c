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

#include "rt_core.h"
#include "rt_request.h"
#include "rt_rep.h"
#include "rt_utils.h"
#include "rt_uuid.h"
#include "rt_string.h"
#include "rt_mem.h"

#define TAG "RT_CORE_INTROSPECTION"

typedef struct {
	char *url;
	char *protocol;
} ocf_url_info_s;

typedef struct {
	ocf_url_info_s *url_info;
	int url_info_num;
} ocf_url_info_list_s;

static ocf_url_info_list_s g_url_info;
static rt_resource_s *introspection_res = NULL;
static void rt_introspection_get_handler(ocf_request_s request, ocf_rep_decoder_s data);

static void rt_load_introspection(const char *file_path)
{
	//TODO:load json file
	const char *example_url = "/introspection";
	const char *example_protocol = "coap";
	RT_VERIFY_NON_NULL_VOID(file_path, TAG, "introspection file path");
	g_url_info.url_info = rt_mem_alloc(sizeof(ocf_url_info_s) * 1);
	RT_VERIFY_NON_NULL_VOID(g_url_info.url_info, TAG, "g_url_info.url_info");
	g_url_info.url_info[0].url = rt_mem_alloc(strlen(example_url) + 1);
	RT_VERIFY_NON_NULL_VOID(g_url_info.url_info[0].url, TAG, "g_url_info.url_info[0].url");
	rt_strcpy(g_url_info.url_info[0].url, example_url);

	g_url_info.url_info[0].protocol = rt_mem_alloc(strlen(example_protocol) + 1);
	RT_VERIFY_NON_NULL_VOID(g_url_info.url_info[0].protocol, TAG, "g_url_info.url_info[0].protocol");
	rt_strcpy(g_url_info.url_info[0].protocol, example_protocol);
	g_url_info.url_info_num = 1;
}

rt_resource_s *rt_core_make_introspection(const char *introspection_url)
{
	if (introspection_res) {
		RT_LOG_W(TAG, "%s resource is already created!", CORE_INTROSPECTION);
		return introspection_res;
	}

	rt_load_introspection("TODO");
	introspection_res = rt_res_new_resource(CORE_INTROSPECTION);
	RT_VERIFY_NON_NULL_RET(introspection_res, TAG, "duplicate uri or alloc fail", NULL);

	ocf_result_t ret = rt_res_set_interface(introspection_res, OIC_IF_R);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_res_set_interface failed with %d", ret);
		goto errors;
	}

	ret = rt_res_set_interface(introspection_res, OIC_IF_BASELINE);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_res_set_interface failed with %d", ret);
		goto errors;
	}

	ret = rt_res_set_discoverable(introspection_res, true);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_res_set_discoverable failed with %d", ret);
		goto errors;
	}

	const char *str_types[1] = { DISCOVERY_RES_TYPE_INTROSPECTION };
	ret = rt_res_set_resource_types(introspection_res, str_types, 1);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_res_set_resource_types failed with %d", ret);
		goto errors;
	}

	rt_res_set_request_handler(introspection_res, OCF_GET, rt_introspection_get_handler);

	return introspection_res;

errors:
	rt_res_delete_resource(introspection_res);
	rt_core_remove_introspection();
	return NULL;
}

rt_rep_encoder_s *rt_create_introspection_representation(const ocf_request_query_set_s *queries)
{
	rt_rep_encoder_s *introspection_rep = rt_rep_encoder_init(OCF_REP_MAP);
	if (OCF_OK != rt_res_add_if_rt_rep(introspection_rep, introspection_res)) {
		RT_LOG_E(TAG, "rt_res_add_if_rt_rep failed!");
		rt_rep_encoder_release(introspection_rep);
		return NULL;
	}
	rt_res_add_if_rt_rep(introspection_rep, introspection_res);

	rt_rep_encoder_s *url_infos_rep = rt_rep_encoder_init(OCF_REP_ARRAY);
	int i;
	for (i = 0; i < g_url_info.url_info_num; ++i) {
		rt_rep_encoder_s *url_info_rep = rt_rep_encoder_init(OCF_REP_MAP);
		rt_rep_add_string_to_map(url_info_rep, "url", g_url_info.url_info[i].url);
		rt_rep_add_string_to_map(url_info_rep, "protocol", g_url_info.url_info[i].protocol);
		rt_rep_add_map_to_array(url_infos_rep, url_info_rep);
		rt_rep_encoder_release(url_info_rep);
	}

	rt_rep_add_array_to_map(introspection_rep, "urlInfo", url_infos_rep);
	rt_rep_encoder_release(url_infos_rep);
	return introspection_rep;
}

ocf_result_t rt_core_remove_introspection(void)
{
	RT_LOG_D(TAG, "__IN__ %s", __func__);
	int i;
	for (i = 0; i < g_url_info.url_info_num; ++i) {
		if (g_url_info.url_info[i].url) {
			rt_mem_free(g_url_info.url_info[i].url);
		}
		if (g_url_info.url_info[i].protocol) {
			rt_mem_free(g_url_info.url_info[i].protocol);
		}
	}

	if (g_url_info.url_info) {
		rt_mem_free(g_url_info.url_info);
	}
	g_url_info.url_info_num = 0;

	introspection_res = NULL;
	RT_LOG_D(TAG, "__OUT__ %s", __func__);
	return OCF_OK;
}

static void rt_introspection_get_handler(ocf_request_s request, ocf_rep_decoder_s data)
{
	rt_rep_encoder_s *introspection_rep = rt_create_introspection_representation(&((rt_request_s *) request)->queries);
	if (introspection_rep) {
		rt_response_send((rt_request_s *) request, introspection_rep, OCF_RESPONSE_CONTENT);
		rt_rep_encoder_release(introspection_rep);
	} else {
		rt_response_send((rt_request_s *) request, NULL, OCF_RESPONSE_RESOURCE_NOT_FOUND);
	}
}
