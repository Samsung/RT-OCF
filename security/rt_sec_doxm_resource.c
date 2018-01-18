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
#include "rt_sec_doxm_resource.h"
#include "rt_resources_manager.h"
#include "rt_rep.h"
#include "rt_uuid.h"
#include "rt_utils.h"
#include "rt_logger.h"
#include "rt_sec_types.h"
#include "rt_mem.h"

#define TAG "RT_DOXM"

static rt_sec_doxm_s *g_sec_doxm = NULL;
static rt_resource_s *g_doxm_resource = NULL;

// static rt_rep_encoder_s *rt_convert_doxm_to_payload(rt_sec_doxm_s *doxm, bool is_response)
rt_rep_encoder_s *rt_convert_doxm_to_payload(rt_sec_doxm_s *doxm, bool is_response)
{
	RT_LOG_D(TAG, "%s : IN", __func__);

	//TODO : Delete this after testing
	if (doxm == NULL) {
		doxm = g_sec_doxm;
	}
	//TODO : Delete this after testing

	RT_VERIFY_NON_NULL_RET(doxm, TAG, "doxm", NULL);

	rt_rep_encoder_s *rep = rt_rep_encoder_init(OCF_REP_MAP);

	if (is_response) {
		rt_res_add_if_rt_rep(rep, g_doxm_resource);
	}
	// Set oxms
	rt_rep_encoder_s *oxms_array = rt_rep_encoder_init(OCF_REP_ARRAY);
	int i;
	for (i = 0; i < doxm->oxms.len; ++i) {
		rt_rep_add_int_to_array(oxms_array, doxm->oxms.oxm[i]);
	}
	rt_rep_add_array_to_map(rep, OCF_DOXM_OXMS, oxms_array);
	rt_rep_encoder_release(oxms_array);

	// Set oxmsel
	rt_rep_add_int_to_map(rep, OCF_DOXM_OXMSEL, doxm->oxmsel);

	// Set sct
	rt_rep_add_int_to_map(rep, OCF_DOXM_SCT, doxm->sct);

	// Set owned
	rt_rep_add_bool_to_map(rep, OCF_DOXM_OWNED, doxm->owned);

	// Set deviceuuid
	rt_uuid_str_t temp_uuid = { 0, };
	rt_uuid_uuid2str(doxm->deviceuuid, temp_uuid, RT_UUID_STR_LEN);
	rt_rep_add_string_to_map(rep, OCF_DOXM_DEVICEUUID, temp_uuid);

	// Set devowneruuid
	rt_uuid_uuid2str(doxm->devowneruuid, temp_uuid, RT_UUID_STR_LEN);
	rt_rep_add_string_to_map(rep, OCF_DOXM_DEVOWNERUUID, temp_uuid);
	
	// Set rowneruuid
	rt_uuid_uuid2str(doxm->rowneruuid, temp_uuid, RT_UUID_STR_LEN);
	rt_rep_add_string_to_map(rep, OCF_ROWNERUUID_NAME, temp_uuid);
	RT_LOG_D(TAG, "%s : OUT", __func__);
	return rep;
}

static void get_handler_func(ocf_request_s request, ocf_rep_decoder_s data)
{
	RT_LOG_D(TAG, "%s : IN", __func__);
	rt_rep_encoder_s *rep = rt_convert_doxm_to_payload(g_sec_doxm, true);

	RT_VERIFY_NON_NULL_VOID(rep, TAG, "rep is NULL");
	rt_response_send((rt_request_s *) request, rep, OCF_RESPONSE_CONTENT);
	rt_rep_encoder_release(rep);

	RT_LOG_D(TAG, "%s : OUT", __func__);
}

static void post_handler_func(ocf_request_s request, ocf_rep_decoder_s data)
{
	RT_LOG_D(TAG, "%s : IN", __func__);

	//TODO : Need to update
	// ocf_result_t ret = OCF_ERROR;
	// rt_sec_doxm_s new_doxm;

	// ret = rt_convert_payload_to_doxm(new_doxm, data, true);
	// if (OCF_OK == ret)
	// {
	/*TODO : Check to whether property is read only or R/W ?
	   if the property is R/W, updating g_sec_doxm,
	   otherwise, sending error response
	 */
	// rt_rep_encoder_s *rep = rt_convert_doxm_to_payload(g_sec_doxm, false);
	// rt_sec_save_ps(RT_SEC_DOXM, rep);
	// }

	RT_LOG_D(TAG, "%s : OUT", __func__);
}

static ocf_result_t rt_convert_payload_to_doxm(rt_rep_decoder_s *rep, rt_sec_doxm_s *out, bool is_request)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	ocf_result_t ret = OCF_OK;
	rt_rep_decoder_s oxms;

	// Set oxms
	ret = rt_rep_get_array_from_map(rep, OCF_DOXM_OXMS, &oxms);
	if ((OCF_OK != ret) && (!is_request)) {
		RT_LOG_E(TAG, "oxms does not exist");
		goto exit;
	} else if (OCF_OK == ret) {
		if (OCF_OK == rt_rep_get_array_length(&oxms, &out->oxms.len)) {
			out->oxms.oxm = (int *)rt_mem_alloc(sizeof(int) * (out->oxms.len));
			RT_VERIFY_NON_NULL_RET(out->oxms.oxm, TAG, "out->oxms.oxm is null", OCF_MEM_FULL);
			int i;
			for (i = 0; i < out->oxms.len; i++) {
				rt_rep_get_int_from_array(&oxms, i, &out->oxms.oxm[i]);
			}
		} else {
			RT_LOG_E(TAG, "oxms is invalid");
			ret = OCF_ERROR;
			goto exit;
		}
	}
	// Set oxmsel
	ret = rt_rep_get_int_from_map(rep, OCF_DOXM_OXMSEL, &out->oxmsel);
	if ((OCF_OK != ret) && (!is_request)) {
		RT_LOG_E(TAG, "oxmsel does not exist");
		goto exit;
	}
	// Set sct
	ret = rt_rep_get_int_from_map(rep, OCF_DOXM_SCT, &out->sct);
	if ((OCF_OK != ret) && (!is_request)) {
		RT_LOG_E(TAG, "sct does not exist");
		goto exit;
	}
	// Set owned
	ret = rt_rep_get_bool_from_map(rep, OCF_DOXM_OWNED, &out->owned);
	if ((OCF_OK != ret) && (!is_request)) {
		RT_LOG_E(TAG, "owned does not exist");
		goto exit;
	}
	// Set deviceuuid
	rt_uuid_str_t temp_uuid_str = { 0, };
	rt_uuid_t temp_uuid;
	ret = rt_rep_get_string_from_map(rep, OCF_DOXM_DEVICEUUID, temp_uuid_str);
	if ((OCF_OK != ret) && (!is_request)) {
		RT_LOG_E(TAG, "deviceuuid does not exist");
		goto exit;
	} else if (OCF_OK == ret) {
		rt_uuid_str2uuid(temp_uuid_str, temp_uuid);
		if (rt_uuid_is_empty(temp_uuid) && (!is_request)) {
			rt_uuid_generate(out->deviceuuid);
		} else if (strlen(temp_uuid_str) == (RT_UUID_STR_LEN - 1)) {
			ret = rt_uuid_str2uuid(temp_uuid_str, out->deviceuuid);
			if (OCF_OK != ret) {
				RT_LOG_E(TAG, "deviceuuid is invalid");
				goto exit;
			}
		} else {
			RT_LOG_E(TAG, "deviceuuid is invalid");
			ret = OCF_INVALID_DEVICE_INFO;
			goto exit;
		}
	}
	// Set devowneruuid
	memset(temp_uuid_str, 0, RT_UUID_STR_LEN);
	ret = rt_rep_get_string_from_map(rep, OCF_DOXM_DEVOWNERUUID, temp_uuid_str);
	if ((OCF_OK != ret) && (!is_request)) {
		RT_LOG_E(TAG, "devowneruuid does not exist");
		goto exit;
	} else if (OCF_OK == ret) {
		rt_uuid_str2uuid(temp_uuid_str, temp_uuid);
		if (rt_uuid_is_empty(temp_uuid)) {
			memcpy(out->devowneruuid, out->deviceuuid, RT_UUID_LEN);
		} else if (strlen(temp_uuid_str) == (RT_UUID_STR_LEN - 1)) {
			ret = rt_uuid_str2uuid(temp_uuid_str, out->devowneruuid);
			if (OCF_OK != ret) {
				RT_LOG_E(TAG, "devowneruuid is invalid");
				goto exit;
			}
		} else {
			RT_LOG_E(TAG, "devowneruuid is invalid");
			ret = OCF_INVALID_DEVICE_INFO;
			goto exit;
		}
	}
	// Set rowneruuid
	memset(temp_uuid_str, 0, RT_UUID_STR_LEN);
	ret = rt_rep_get_string_from_map(rep, OCF_ROWNERUUID_NAME, temp_uuid_str);
	if ((OCF_OK != ret) && (!is_request)) {
		RT_LOG_E(TAG, "rowneruuid does not exist");
		goto exit;
	} else if (OCF_OK == ret) {
		if (strlen(temp_uuid_str) == (RT_UUID_STR_LEN - 1)) {
			ret = rt_uuid_str2uuid(temp_uuid_str, out->rowneruuid);
			if (OCF_OK != ret) {
				RT_LOG_E(TAG, "rowneruuid is invalid");
				goto exit;
			}
		} else {
			RT_LOG_E(TAG, "rowneruuid is invalid");
			ret = OCF_INVALID_DEVICE_INFO;
			goto exit;
		}
	}

exit:
	RT_LOG_D(TAG, "%s OUT", __func__);
	return ret;
}

static ocf_result_t rt_sec_init_doxm_resource(void)
{
	RT_LOG_D(TAG, "%s : IN", __func__);
	if (g_doxm_resource != NULL) {
		RT_LOG_D(TAG, "doxm already init");
		return OCF_ALREADY_INIT;
	}

	g_doxm_resource = rt_res_new_resource(OCF_DOXM_HREF);
	rt_res_set_discoverable(g_doxm_resource, true);
	rt_res_set_observable(g_doxm_resource, false);
	rt_res_set_interface(g_doxm_resource, OIC_IF_BASELINE);
	const char *g_doxm_resource_types[1] = {
		OCF_DOXM_RT
	};
	rt_res_set_resource_types(g_doxm_resource, g_doxm_resource_types, 1);
	// TODO : Add put, post, delete handler
	rt_res_set_request_handler(g_doxm_resource, OCF_GET, get_handler_func);
	rt_res_set_secure(g_doxm_resource, true);
	rt_res_set_resource_protocol(g_doxm_resource, OCF_COAP | OCF_COAPS | OCF_COAP_TCP | OCF_COAPS_TCP);
	RT_LOG_D(TAG, "%s : OUT", __func__);
	return rt_res_register_resource(g_doxm_resource);
}

ocf_result_t rt_sec_doxm_init(void)
{
	RT_LOG_D(TAG, "%s : IN", __func__);
	rt_rep_decoder_s *rep;

	if (g_sec_doxm != NULL) {
		RT_LOG_W(TAG, "doxm already init");
		return OCF_ALREADY_INIT;
	}
	g_sec_doxm = (rt_sec_doxm_s *) rt_mem_alloc(sizeof(rt_sec_doxm_s));
	RT_VERIFY_NON_NULL_RET(g_sec_doxm, TAG, "g_sec_doxm is null", OCF_MEM_FULL);

	ocf_result_t ret = rt_sec_load_ps(RT_SEC_DOXM, &rep);
	if (OCF_OK != ret) {
		goto exit;
	}

	memset(g_sec_doxm->deviceuuid, 0, RT_UUID_LEN);
	memset(g_sec_doxm->devowneruuid, 0, RT_UUID_LEN);
	memset(g_sec_doxm->rowneruuid, 0, RT_UUID_LEN);
	g_sec_doxm->oxms.oxm = NULL;

	if (rt_convert_payload_to_doxm(rep, g_sec_doxm, false) != OCF_OK) {
		ret = OCF_ERROR;
		goto exit;
	}
	rt_rep_decoder_release(rep);
	rep = NULL;
	rt_sec_init_doxm_resource();

exit:
	if (rep) {
		rt_rep_decoder_release(rep);
	}
	RT_LOG_D(TAG, "%s : OUT", __func__);
	return ret;
}

ocf_result_t rt_sec_doxm_terminate(void)
{
	RT_LOG_D(TAG, "%s : IN", __func__);

	if (NULL == g_sec_doxm) {
		RT_LOG_W(TAG, "doxm resource is not initialized");
		return OCF_ERROR;
	}

	if (NULL != g_sec_doxm->oxms.oxm) {
		rt_mem_free(g_sec_doxm->oxms.oxm);
		g_sec_doxm->oxms.oxm = NULL;
	}

	rt_mem_free(g_sec_doxm);
	g_sec_doxm = NULL;

	// Check : Currently, g_doxm_resource will release in ocf_terminate -> rt_resource_manager_terminate
	g_doxm_resource = NULL;
	RT_LOG_D(TAG, "%s : OUT", __func__);
	return OCF_OK;
}

void rt_sec_doxm_get_deviceuuid_byte(rt_uuid_t deviceuuid)
{
	RT_LOG_D(TAG, "%s : IN", __func__);
	memcpy(deviceuuid, g_sec_doxm->deviceuuid, RT_UUID_LEN);
	RT_LOG_D(TAG, "%s : OUT", __func__);
}

ocf_result_t rt_sec_doxm_get_deviceuuid(char *deviceuuid)
{
	RT_VERIFY_NON_NULL(deviceuuid, TAG, "deviceuuid");
	return rt_uuid_uuid2str(g_sec_doxm->deviceuuid, deviceuuid, RT_UUID_STR_LEN);
}

ocf_result_t rt_sec_doxm_get_devowneruuid(char *devowneruuid)
{
	if (rt_uuid_is_empty(g_sec_doxm->devowneruuid)) {
		return rt_uuid_uuid2str(g_sec_doxm->deviceuuid, devowneruuid, RT_UUID_STR_LEN);
	}
	return rt_uuid_uuid2str(g_sec_doxm->devowneruuid, devowneruuid, RT_UUID_STR_LEN);
}
