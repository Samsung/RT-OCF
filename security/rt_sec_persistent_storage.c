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
#include "rt_utils.h"
#include "rt_mem.h"
#include "rt_sec_persistent_storage.h"

#define TAG "RT_SEC_PS"

#define SVR_DB_DAT_FILE_NAME "ocf_svr_db.dat"

static rt_persistent_storage_handler_s *g_ps_sec_handler[RT_SEC_MAX];

static ocf_result_t rt_check_ps_is_valid(rt_persistent_storage_handler_s *svr_handler)
{
	RT_LOG_D(TAG, "In %s", __func__);
	FILE *fp = NULL;

	RT_VERIFY_NON_NULL_RET(svr_handler, TAG, "SVR Handler is null", OCF_INVALID_PARAM);

	fp = svr_handler->open(SVR_DB_DAT_FILE_NAME, "rb");
	if (NULL == fp) {
		RT_LOG_E(TAG, "DB file cannot be opened");
		return OCF_SVR_DB_NOT_EXIST;
	}
	svr_handler->close(fp);

	RT_LOG_D(TAG, "Out %s", __func__);

	return OCF_OK;
}

ocf_result_t rt_sec_register_ps_handler(rt_persistent_storage_handler_s *ps_doxm, rt_persistent_storage_handler_s *ps_pstat, rt_persistent_storage_handler_s *ps_cred, rt_persistent_storage_handler_s *ps_acl2)
{
	RT_LOG_D(TAG, "In %s", __func__);
	RT_VERIFY_NON_NULL_RET(ps_doxm, TAG, "ps_doxm is NULL", OCF_INVALID_PARAM);
	RT_VERIFY_NON_NULL_RET(ps_pstat, TAG, "ps_pstat is NULL", OCF_INVALID_PARAM);
	RT_VERIFY_NON_NULL_RET(ps_cred, TAG, "ps_cred is NULL", OCF_INVALID_PARAM);
	RT_VERIFY_NON_NULL_RET(ps_acl2, TAG, "ps_acl2 is NULL", OCF_INVALID_PARAM);

	g_ps_sec_handler[RT_SEC_DOXM] = ps_doxm;
	g_ps_sec_handler[RT_SEC_PSTAT] = ps_pstat;
	g_ps_sec_handler[RT_SEC_CRED] = ps_cred;
	g_ps_sec_handler[RT_SEC_ACL2] = ps_acl2;

	ocf_result_t res = OCF_SVR_DB_NOT_EXIST;

	int i, j;
	for (i = RT_SEC_DOXM; i < RT_SEC_MAX; i++) {
		res = rt_check_ps_is_valid(g_ps_sec_handler[i]);

		if (OCF_OK != res) {
			RT_LOG_E(TAG, "Persistent storage is not normal");
			for (j = RT_SEC_DOXM; j < RT_SEC_MAX; j++) {
				g_ps_sec_handler[j] = NULL;
			}
			break;
		}
	}
	RT_LOG_D(TAG, "Out %s", __func__);
	return res;
}

ocf_result_t rt_sec_load_ps(const rt_sec_resources_t sec_resource, rt_rep_decoder_s **rep)
{
	RT_LOG_D(TAG, "IN %s", __func__);
	RT_VERIFY_NON_NULL_RET(rep, TAG, "rep is NULL", OCF_INVALID_PARAM);
	RT_VERIFY_NON_NULL_RET(g_ps_sec_handler[sec_resource], TAG, "g_ps_sec_handler is NULL", OCF_INVALID_PARAM);
	rt_persistent_storage_handler_s *svr_handler = g_ps_sec_handler[sec_resource];

	FILE *fp = svr_handler->open(SVR_DB_DAT_FILE_NAME, "rb");

	if (fp == NULL) {
		RT_LOG_E(TAG, "it is failed to open ps file");
		return OCF_SVR_DB_NOT_EXIST;
	}

	long file_size = 0;
	uint8_t *data = NULL;
	if (fseek(fp, 0, SEEK_END) == 0 && (file_size = ftell(fp)) >= 0) {
		rewind(fp);
		RT_LOG_D(TAG, "File size : %d", file_size);
		data = (uint8_t *) rt_mem_alloc(file_size);
		RT_VERIFY_NON_NULL_RET(data, TAG, "data malloc failed!", OCF_MEM_FULL);
		svr_handler->read(data, 1, file_size, fp);
	}
	svr_handler->close(fp);

	*rep = rt_rep_decoder_init(data, (uint16_t) file_size);
	rt_mem_free(data);

	RT_LOG_D(TAG, "Out %s", __func__);

	return OCF_OK;
}

ocf_result_t rt_sec_save_ps(const rt_sec_resources_t sec_resource, rt_rep_encoder_s *rep)
{
	RT_LOG_D(TAG, "IN %s", __func__);
	RT_VERIFY_NON_NULL_RET(rep, TAG, "rep is NULL", OCF_INVALID_PARAM);
	RT_VERIFY_NON_NULL_RET(g_ps_sec_handler[sec_resource], TAG, "g_ps_sec_handler is NULL", OCF_INVALID_PARAM);
	rt_persistent_storage_handler_s *svr_handler = g_ps_sec_handler[sec_resource];

	FILE *fp = svr_handler->open(SVR_DB_DAT_FILE_NAME, "wb");
	RT_VERIFY_NON_NULL_RET(fp, TAG, "It is failed to open file!", OCF_ERROR);

	if (0 >= svr_handler->write(rep->payload, 1, rep->payload_size, fp)) {
		RT_LOG_E(TAG, "It is failed to save file");
		return OCF_ERROR;
	}
	svr_handler->close(fp);

	return OCF_OK;
}
