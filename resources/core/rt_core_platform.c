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
#include "rt_string.h"
#include "rt_mem.h"

#define TAG "RT_CORE_P"

typedef struct {
	char *pi;					// platform id
	char *mnmn;					//manufacturer name
} rt_platform_info_s;			// TODO: think about rename

static rt_platform_info_s g_platform_info;
static rt_resource_s *platform_res = NULL;
static void rt_platform_info_get_handler(ocf_request_s request, ocf_rep_decoder_s data);

rt_resource_s *rt_core_make_oic_p(const char *manufacturer_name)
{
	if (platform_res) {
		RT_LOG_W(TAG, "%s resource is already created!", CORE_P);
		return platform_res;
	}

	memset(&g_platform_info, 0, sizeof(g_platform_info));	//TODO: if g_platform_info is already set, pi, mnmn may leak. right?

	platform_res = rt_res_new_resource(CORE_P);
	RT_VERIFY_NON_NULL_RET(platform_res, TAG, "duplicate uri or alloc fail", NULL);

	ocf_result_t ret = rt_res_set_interface(platform_res, OIC_IF_R);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_res_set_interface failed with %d", ret);
		goto errors;
	}

	ret = rt_res_set_interface(platform_res, OIC_IF_BASELINE);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_res_set_interface failed with %d", ret);
		goto errors;
	}

	ret = rt_res_set_discoverable(platform_res, true);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_res_set_discoverable failed with %d", ret);
		goto errors;
	}

	const char *str_types[1] = { DISCOVERY_RES_TYPE_PLATFORM };
	ret = rt_res_set_resource_types(platform_res, str_types, 1);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_res_set_resource_types failed with %d", ret);
		goto errors;
	}
	// TODO : PI should be unique value.
	char *pi = "54919CA5-4101-4AE4-ABCD-353C51AA983C";
	int len = strlen(pi);
	g_platform_info.pi = (char *)rt_mem_alloc(len + 1);

	if (!g_platform_info.pi) {
		RT_LOG_E(TAG, "rt_mem_alloc for [g_platform_info.pi] is failed!");
		goto errors;
	}
	rt_strncpy(g_platform_info.pi, pi, len);

	len = strlen(manufacturer_name);
	g_platform_info.mnmn = (char *)rt_mem_alloc(len + 1);
	if (!g_platform_info.mnmn) {
		RT_LOG_E(TAG, "rt_mem_alloc for [g_platform_info.mnmn] is failed!");
		goto errors;
	}
	rt_strncpy(g_platform_info.mnmn, manufacturer_name, len);

	rt_res_set_request_handler(platform_res, OCF_GET, rt_platform_info_get_handler);

	return platform_res;

errors:
	rt_res_delete_resource(platform_res);
	rt_core_remove_oic_p();
	return NULL;
}

static rt_rep_encoder_s *rt_create_oic_p_representation(const ocf_request_query_set_s *queries)
{
	rt_rep_encoder_s *oic_p_rep = rt_rep_encoder_init(OCF_REP_MAP);
	if (OCF_OK != rt_res_add_if_rt_rep(oic_p_rep, platform_res)) {
		RT_LOG_E(TAG, "rt_res_add_if_rt_rep failed!");
		rt_rep_encoder_release(oic_p_rep);
		return NULL;
	}
	rt_rep_add_string_to_map(oic_p_rep, "pi", g_platform_info.pi);
	rt_rep_add_string_to_map(oic_p_rep, "mnmn", g_platform_info.mnmn);

	return oic_p_rep;
}

ocf_result_t rt_core_remove_oic_p(void)
{
	if (g_platform_info.pi) {
		rt_mem_free(g_platform_info.pi);
	}
	if (g_platform_info.mnmn) {
		rt_mem_free(g_platform_info.mnmn);
	}

	memset(&g_platform_info, 0, sizeof(g_platform_info));

	platform_res = NULL;

	return OCF_OK;
}

static void rt_platform_info_get_handler(ocf_request_s request, ocf_rep_decoder_s data)
{
	rt_rep_encoder_s *oic_p_rep = rt_create_oic_p_representation(&((rt_request_s *) request)->queries);

	if (oic_p_rep) {
		rt_response_send((rt_request_s *) request, oic_p_rep, OCF_RESPONSE_CONTENT);
		rt_rep_encoder_release(oic_p_rep);
	} else {
		rt_response_send((rt_request_s *) request, NULL, OCF_RESPONSE_RESOURCE_NOT_FOUND);
	}
}
