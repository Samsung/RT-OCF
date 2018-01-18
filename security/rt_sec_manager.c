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

#include "rt_sec_cred_resource.h"
#include "rt_sec_doxm_resource.h"
#include "rt_logger.h"
#include "rt_sec_types.h"
#include "rt_ssl.h"

#define TAG "RT_SEC_MANAGER"

ocf_result_t rt_sec_terminate(void)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	rt_ssl_terminate();

	rt_sec_doxm_terminate();
	rt_sec_cred_terminate();
	rt_sec_acl2_terminate();
	rt_sec_pstat_terminate();

	RT_LOG_D(TAG, "%s OUT", __func__);
	return OCF_OK;
}

ocf_result_t rt_sec_init(void)
{
	RT_LOG_D(TAG, "%s INT", __func__);
	ocf_result_t ret = OCF_ERROR;

	if (OCF_OK != (ret = rt_sec_doxm_init())) {
		goto error;
	}
	if (OCF_OK != (ret = rt_sec_cred_init())) {
		goto error;
	}
	if (OCF_OK != (ret = rt_sec_acl2_init())) {
		goto error;
	}
	if (OCF_OK != (ret = rt_sec_pstat_init())) {
		goto error;
	}

	rt_ssl_register_psk_handler(rt_sec_cred_get_psk);

	if (OCF_OK != rt_ssl_init()) {
		RT_LOG_E(TAG, "fail to init SSL ");
		goto error;
	}

	RT_LOG_D(TAG, "%s OUT", __func__);
	return ret;

error:
	rt_sec_terminate();

	RT_LOG_D(TAG, "%s OUT", __func__);
	return ret;
}
