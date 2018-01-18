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
#include "rt_sec_pstat_resource.h"
#include "rt_resources_manager.h"
#include "rt_utils.h"
#include "rt_logger.h"
#include "rt_rep.h"
#include "rt_sec_types.h"
#include "rt_mem.h"

#define TAG "RT_SEC_PSTAT"

rt_sec_pstat_s *g_sec_pstat = NULL;
static rt_resource_s *g_pstat_resource = NULL;

static void get_handler_func(ocf_request_s request, ocf_rep_decoder_s data)
{
	RT_LOG_D(TAG, "%s : IN", __func__);
	rt_rep_encoder_s *rep = rt_convert_pstat_to_payload(g_sec_pstat, true);

	rt_response_send((rt_request_s *) request, rep, OCF_RESPONSE_CONTENT);
	rt_rep_encoder_release(rep);

	RT_LOG_D(TAG, "%s : OUT", __func__);
}

static ocf_result_t rt_sec_init_pstat_resource(void)
{
	RT_LOG_D(TAG, "%s : IN", __func__);

	if (g_pstat_resource != NULL) {
		RT_LOG_W(TAG, "pstat resource already init");
		return OCF_ALREADY_INIT;
	}

	g_pstat_resource = rt_res_new_resource(OCF_PSTAT_HREF);
	rt_res_set_discoverable(g_pstat_resource, true);
	rt_res_set_observable(g_pstat_resource, false);
	rt_res_set_interface(g_pstat_resource, OIC_IF_BASELINE);
	const char *pstat_resource_types[1] = { OCF_PSTAT_RT };
	rt_res_set_resource_types(g_pstat_resource, pstat_resource_types, 1);
	// TODO : Add put, post, delete handler
	rt_res_set_request_handler(g_pstat_resource, OCF_GET, get_handler_func);
	rt_res_set_secure(g_pstat_resource, true);
	// TODO : Should sync with device protocol
	rt_res_set_resource_protocol(g_pstat_resource, OCF_COAP | OCF_COAPS | OCF_COAP_TCP | OCF_COAPS_TCP);

	RT_LOG_D(TAG, "%s : OUT", __func__);

	return rt_res_register_resource(g_pstat_resource);
}

ocf_result_t rt_sec_pstat_init(void)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	if (g_sec_pstat != NULL) {
		RT_LOG_W(TAG, "pstat already init");
		return OCF_ALREADY_INIT;
	}

	rt_rep_decoder_s *rep = NULL;

	ocf_result_t ret = rt_sec_load_ps(RT_SEC_PSTAT, &rep);
	if (OCF_OK != ret) {
		goto exit;
	}

	g_sec_pstat = (rt_sec_pstat_s *) rt_mem_alloc(sizeof(rt_sec_pstat_s));
	RT_VERIFY_NON_NULL_RET(g_sec_pstat, TAG, "g_sec_pstat", OCF_MEM_FULL);
	memset(g_sec_pstat->rowner_id, 0, RT_UUID_LEN);

	if (OCF_OK != rt_convert_payload_to_pstat(rep, g_sec_pstat, false)) {
		ret = OCF_ERROR;
		goto exit;
	}

	rt_sec_init_pstat_resource();

exit:
	if (rep) {
		rt_rep_decoder_release(rep);
		rep = NULL;
	}
	RT_LOG_D(TAG, "%s : OUT", __func__);

	return ret;
}

ocf_result_t rt_sec_pstat_terminate(void)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	if (NULL == g_sec_pstat) {
		RT_LOG_W(TAG, "g_sec_pstat resource is not initialized");
		return OCF_ERROR;
	}

	rt_mem_free(g_sec_pstat);
	g_sec_pstat = NULL;
	g_pstat_resource = NULL;
	RT_LOG_D(TAG, "%s OUT", __func__);
	return OCF_OK;
}

rt_rep_encoder_s *rt_convert_pstat_to_payload(rt_sec_pstat_s *pstat, bool is_response)
{
	RT_LOG_D(TAG, "%s : IN", __func__);

	RT_VERIFY_NON_NULL_RET(pstat, TAG, "pstat is NULL", NULL);

	rt_rep_encoder_s *rep = rt_rep_encoder_init(OCF_REP_MAP);

	if (is_response) {
		rt_res_add_if_rt_rep(rep, g_pstat_resource);
	}

	rt_rep_encoder_s *dos_map = rt_rep_encoder_init(OCF_REP_MAP);
	rt_rep_add_int_to_map(dos_map, OCF_PSTAT_STATE, pstat->dos.state);
	rt_rep_add_bool_to_map(dos_map, OCF_PSTAT_PENDING, pstat->dos.pending);
	rt_rep_add_map_to_map(rep, OCF_PSTAT_DOS, dos_map);
	rt_rep_encoder_release(dos_map);

	rt_rep_add_bool_to_map(rep, OCF_PSTAT_ISOP, pstat->isop);
	rt_rep_add_int_to_map(rep, OCF_PSTAT_CM, pstat->cm);
	rt_rep_add_int_to_map(rep, OCF_PSTAT_TM, pstat->tm);
	rt_rep_add_int_to_map(rep, OCF_PSTAT_OM, pstat->om);
	rt_rep_add_int_to_map(rep, OCF_PSTAT_SM, pstat->sm);

	char uuid_str[RT_UUID_STR_LEN];
	rt_uuid_uuid2str(pstat->rowner_id, uuid_str, RT_UUID_STR_LEN);
	rt_rep_add_string_to_map(rep, OCF_ROWNERUUID_NAME, uuid_str);

	RT_LOG_D(TAG, "%s : OUT", __func__);
	return rep;
}

ocf_result_t rt_convert_payload_to_pstat(rt_rep_decoder_s *rep, rt_sec_pstat_s *out, bool is_request)
{
	RT_LOG_D(TAG, "%s : IN", __func__);

	ocf_result_t ret = OCF_OK;

	rt_rep_decoder_s dos_map;
	ret = rt_rep_get_map_from_map(rep, OCF_PSTAT_DOS, &dos_map);
	if ((OCF_OK != ret) && (!is_request)) {
		RT_LOG_E(TAG, "dos does not exist");
		goto exit;
	} else if (OCF_OK == ret) {
		if (OCF_OK != rt_rep_get_int_from_map(&dos_map, OCF_PSTAT_STATE, (int *)&out->dos.state)) {
			RT_LOG_E(TAG, "OCF_PSTAT_STATE does not exist");
			goto exit;
		}
		if (OCF_OK != rt_rep_get_bool_from_map(&dos_map, OCF_PSTAT_PENDING, &out->dos.pending)) {
			RT_LOG_E(TAG, "OCF_PSTAT_PENDING does not exist");
			goto exit;
		}
	}

	ret = rt_rep_get_bool_from_map(rep, OCF_PSTAT_ISOP, &out->isop);
	if ((OCF_OK != ret) && (!is_request)) {
		RT_LOG_E(TAG, "OCF_PSTAT_ISOP does not exist");
		goto exit;
	}

	ret = rt_rep_get_int_from_map(rep, OCF_PSTAT_CM, (int *)&out->cm);
	if ((OCF_OK != ret) && (!is_request)) {
		RT_LOG_E(TAG, "OCF_PSTAT_CM does not exist");
		goto exit;
	}

	ret = rt_rep_get_int_from_map(rep, OCF_PSTAT_TM, (int *)&out->tm);
	if ((OCF_OK != ret) && (!is_request)) {
		RT_LOG_E(TAG, "OCF_PSTAT_TM does not exist");
		goto exit;
	}

	ret = rt_rep_get_int_from_map(rep, OCF_PSTAT_OM, (int *)&out->om);
	if ((OCF_OK != ret) && (!is_request)) {
		RT_LOG_E(TAG, "OCF_PSTAT_OM does not exist");
		goto exit;
	}

	ret = rt_rep_get_int_from_map(rep, OCF_PSTAT_SM, (int *)&out->sm);
	if ((OCF_OK != ret) && (!is_request)) {
		RT_LOG_E(TAG, "OCF_PSTAT_SM does not exist");
		goto exit;
	}

	char uuid_str[RT_UUID_STR_LEN];
	ret = rt_rep_get_string_from_map(rep, OCF_ROWNERUUID_NAME, uuid_str);
	if ((OCF_OK != ret) && (!is_request)) {
		RT_LOG_E(TAG, "OCF_ROWNERUUID_NAME does not exist");
		goto exit;
	} else if (OCF_OK == ret) {
		if (strlen(uuid_str) == (RT_UUID_STR_LEN - 1)) {
			ret = rt_uuid_str2uuid(uuid_str, out->rowner_id);
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
