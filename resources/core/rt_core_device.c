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

#define TAG "RT_CORE_D"

typedef struct {
//  char *icv;   // TODO:: DISCOVERY_CORE_RES_DEVICE_SPEC_VER would be applied
	char *dmv;
	char *n;
	// void *ld;
	// void *dmn;
} rt_device_info_s;				// TODO: think about rename

static rt_device_info_s g_device_info;
static rt_resource_s *device_res = NULL;
static void rt_device_info_get_handler(ocf_request_s request, ocf_rep_decoder_s data);

rt_resource_s *rt_core_make_oic_d(const char *data_model_ver)
{
	if (device_res) {
		RT_LOG_W(TAG, "%s resource is already created!", CORE_D);
		return device_res;
	}

	memset(&g_device_info, 0, sizeof(g_device_info));	//TODO: if g_device_info is already set, dmv, n may leak. right?

	device_res = rt_res_new_resource(CORE_D);
	RT_VERIFY_NON_NULL_RET(device_res, TAG, "duplicate uri or alloc fail", NULL);

	ocf_result_t ret = rt_res_set_interface(device_res, OIC_IF_R);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_res_set_interface failed with %d", ret);
		goto errors;
	}

	ret = rt_res_set_interface(device_res, OIC_IF_BASELINE);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_res_set_interface failed with %d", ret);
		goto errors;
	}

	ret = rt_res_set_discoverable(device_res, true);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_res_set_discoverable failed with %d", ret);
		goto errors;
	}

	const char *str_types[1] = { DISCOVERY_RES_TYPE_DEVICE };
	ret = rt_res_set_resource_types(device_res, str_types, 1);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_res_set_resource_types failed with %d", ret);
		goto errors;
	}
	// int len = strlen(spec_ver);
	// g_device_info.icv = (char *)rt_mem_alloc(len + 1);
	// strncpy(g_device_info.icv, spec_ver, len + 1);

	int len = strlen(data_model_ver);
	g_device_info.dmv = (char *)rt_mem_alloc(len + 1);
	if (!g_device_info.dmv) {
		RT_LOG_E(TAG, "rt_mem_alloc for [g_device_info.dmv] is failed!");
		goto errors;
	}
	rt_strncpy(g_device_info.dmv, data_model_ver, len);

	g_device_info.n = NULL;

	rt_res_set_request_handler(device_res, OCF_GET, rt_device_info_get_handler);

	return device_res;

errors:
	rt_res_delete_resource(device_res);
	rt_core_remove_oic_d();
	return NULL;
}

ocf_result_t rt_core_set_oic_d_name_opt(const char *value)
{
	RT_VERIFY_NON_NULL_RET(value, TAG, "Name  is null", OCF_INVALID_PARAM);

	int len = strlen(value);
	g_device_info.n = (char *)rt_mem_alloc(len + 1);
	RT_VERIFY_NON_NULL_RET(g_device_info.n, TAG, "g_device_info.n", OCF_MEM_FULL);
	rt_strncpy(g_device_info.n, value, len);

	return OCF_OK;
}

ocf_result_t rt_core_add_oic_d_type(const char **device_types, uint8_t device_types_count)
{
	RT_VERIFY_NON_NULL_RET(device_types, TAG, "device type  is null", OCF_INVALID_PARAM);
	RT_VERIFY_NON_NULL_RET(device_res, TAG, "oic/d is not ready. please ocf_init first", OCF_ERROR);

	return rt_res_set_resource_types(device_res, device_types, device_types_count);
}

rt_rep_encoder_s *rt_create_oic_d_representation(const ocf_request_query_set_s *queries)
{
	rt_rep_encoder_s *oic_d_rep = rt_rep_encoder_init(OCF_REP_MAP);
	if (OCF_OK != rt_res_add_if_rt_rep(oic_d_rep, device_res)) {
		RT_LOG_E(TAG, "rt_res_add_if_rt_rep failed!");
		rt_rep_encoder_release(oic_d_rep);
		return NULL;
	}

	if (g_device_info.n) {
		rt_rep_add_string_to_map(oic_d_rep, "n", g_device_info.n);
	}

	rt_rep_add_string_to_map(oic_d_rep, "icv", DEVICE_PROPERTY_SPEC_VER);
	rt_rep_add_string_to_map(oic_d_rep, "dmv", g_device_info.dmv);

	char uuid_str[RT_UUID_STR_LEN];
	rt_sec_doxm_get_deviceuuid(uuid_str);
	rt_rep_add_string_to_map(oic_d_rep, "di", uuid_str);
	rt_sec_doxm_get_devowneruuid(uuid_str);
	rt_rep_add_string_to_map(oic_d_rep, "piid", uuid_str);

	return oic_d_rep;
}

ocf_result_t rt_core_remove_oic_d(void)
{
	if (g_device_info.n) {
		rt_mem_free(g_device_info.n);
	}
	// if (g_device_info.icv) {
	//  rt_mem_free(g_device_info.icv);
	// }
	if (g_device_info.dmv) {
		rt_mem_free(g_device_info.dmv);
	}

	memset(&g_device_info, 0, sizeof(g_device_info));

	device_res = NULL;

	return OCF_OK;
}

static void rt_device_info_get_handler(ocf_request_s request, ocf_rep_decoder_s data)
{

	rt_rep_encoder_s *oic_d_rep = rt_create_oic_d_representation(&((rt_request_s *) request)->queries);

	if (oic_d_rep) {
		rt_response_send((rt_request_s *) request, oic_d_rep, OCF_RESPONSE_CONTENT);
		rt_rep_encoder_release(oic_d_rep);
	} else {
		rt_response_send((rt_request_s *) request, NULL, OCF_RESPONSE_RESOURCE_NOT_FOUND);
	}

}
