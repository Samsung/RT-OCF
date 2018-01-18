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

#include "rt_thread.h"
#include "rt_logger.h"
#include <string.h>

#define TAG "THREAD"

#ifdef CONFIG_IOTIVITY_RT
#define THREAD_STACK_SIZE   8192
#else
#define THREAD_STACK_SIZE   16384
#endif

#define THREAD_MAX_NAME_SIZE 15

ocf_result_t rt_thread_terminate(rt_thread_s *thread_info, rt_thread_terminate_handler terminate_handler, void *user_data)
{
	if (!thread_info) {
		return OCF_INVALID_PARAM;
	}

	pthread_attr_destroy(&thread_info->thread_attr);

	int ret;
	if (terminate_handler) {
		terminate_handler(user_data);
		ret = pthread_join(thread_info->thread, NULL);
	} else {
		ret = pthread_cancel(thread_info->thread);
	}

	if (ret) {
		RT_LOG_E(TAG, "thread exit failed with %d", ret);
		return OCF_ERROR;
	}

	RT_LOG_D(TAG, "thread exit succeed with %d", ret);
	thread_info->thread = 0;
	return OCF_OK;
}

ocf_result_t rt_thread_init(rt_thread_s *thread_info, rt_thread_handler handler, const char *name, long size, void *user_data)
{
	if (!thread_info || !handler) {
		return OCF_INVALID_PARAM;
	}

	if (name && strlen(name) > THREAD_MAX_NAME_SIZE) {
		RT_LOG_E(TAG, "%s: pthread name can't be longer then %d name=%s", __func__, THREAD_MAX_NAME_SIZE, name);
		return OCF_INVALID_PARAM;
	}

	int r;
	if ((r = pthread_attr_init(&(thread_info->thread_attr)))) {
		RT_LOG_E(TAG, "%s: pthread_attr_init failed, status=%d", __func__, r);
		return OCF_ERROR;
	}
	long stack_size = (0 < size) ? size : THREAD_STACK_SIZE;
	if ((r = pthread_attr_setstacksize(&(thread_info->thread_attr), stack_size))) {
		RT_LOG_E(TAG, "%s: pthread_attr_setstacksize failed, status=%d", __func__, r);
		return OCF_ERROR;
	}
	if ((r = pthread_create(&(thread_info->thread), &(thread_info->thread_attr), handler, user_data))) {
		RT_LOG_E(TAG, "%s: pthred_create failed, status=%d", __func__, r);
		return OCF_ERROR;
	}
	if (name && (r = pthread_setname_np(thread_info->thread, name))) {
		RT_LOG_E(TAG, "%s: pthread_setname_np failed, status=%d, name=%s", __func__, r, name);
		return OCF_ERROR;
	}

	RT_LOG_D(TAG, "thread[%s] is created.", name ? name : "no_name");
	return OCF_OK;
}
