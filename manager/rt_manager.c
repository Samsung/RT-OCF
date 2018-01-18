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

#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <stdlib.h>

#include "rt_manager.h"
#include "rt_mem.h"
#include "rt_thread.h"
#include "rt_random.h"
#include "rt_logger.h"
#include "rt_coap.h"
#include "rt_coap_transactions.h"
#include "rt_ssl.h"
#include "rt_timer.h"
#include "rt_event.h"
#include "rt_utils.h"
#include "rt_string.h"
#include "rt_sec_manager.h"
#include "rt_receive_queue.h"
#include "rt_request_manager.h"
#include "rt_resources_manager.h"

#define TAG "RT_MANAGER"

static rt_thread_s periodic_thread;

static uint8_t periodic_thread_terminate = 0;
static ocf_mode_t g_mode = OCF_CLIENT_SERVER;

typedef enum {
	RT_INIT_DEFAULT = 0,
	RT_EVENT_INIT = (1 << 0),
	RT_MANAGER_INIT_PERIODIC_PROCESS = (1 << 1),
	RT_MEM_POOL_INIT = (1 << 2),
	RT_RES_INIT = (1 << 3),
	RT_REQUEST_INIT = (1 << 4),
	RT_RECEIVE_QUEUE_INIT = (1 << 5),
	RT_COAP_INIT = (1 << 6),
	RT_SECURITY_INIT = (1 << 7)
} rt_init_state_t;

static uint16_t g_ocf_init_state;

static void *rt_manager_periodic_thread_runner(void *data)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	// TODO : rt_event code will be added after figure out issues.
	rt_clock_time_t wakeup_time;
	bool flag;
	while (!periodic_thread_terminate) {
		RT_LOG_D(TAG, "Start new periodic job!");
		rt_coap_check_transactions();
		rt_ssl_check_handshake_timeout();

		wakeup_time = 0;
		flag = rt_coap_get_nearest_wakeup_time_of_transactions(&wakeup_time);
		flag = rt_ssl_get_nearest_wakeup_time_of_peers(&wakeup_time) || flag;

		if (flag) {
			RT_LOG_D(TAG, "Wait until wakeup time...", wakeup_time);
			rt_event_timedwait(wakeup_time);
		} else {
			RT_LOG_D(TAG, "Wait until event signal...");
			rt_event_wait();
		}
	}

	RT_LOG_D(TAG, "%s OUT", __func__);
	return NULL;
}

static ocf_result_t rt_manager_init_periodic_process(void)
{
	if (periodic_thread.thread) {
		RT_LOG(OCF_LOG_ERROR, TAG, "periodic_thread is already created!");
		return OCF_ERROR;
	}

	periodic_thread_terminate = 0;

	return rt_thread_init(&periodic_thread, rt_manager_periodic_thread_runner, "periodic_thread", 0, NULL);
}

static void rt_manager_periodic_thread_terminate_func(void *user_data)
{
	__sync_bool_compare_and_swap(&periodic_thread_terminate, 0, 1);
	rt_event_set_signal();
}

static void rt_manager_terminate_periodic_process(void)
{
	if (!periodic_thread_terminate && periodic_thread.thread) {
		rt_thread_terminate(&periodic_thread, rt_manager_periodic_thread_terminate_func, NULL);
	}
}

ocf_result_t ocf_init(ocf_mode_t mode, const char *manufacturer_name, ocf_dmv_t data_model_ver_bit)
{
	g_ocf_init_state = RT_INIT_DEFAULT;
	RT_VERIFY_NON_NULL_RET(manufacturer_name, TAG, "manufacturer_name is NULL", OCF_INVALID_PARAM);
	char data_model_ver[50] = OCF_RES_100_VALUE;
	ocf_result_t ret = OCF_OK;

	if (!(mode == OCF_SERVER || mode == OCF_CLIENT_SERVER || mode == OCF_CLIENT)) {
		return OCF_INVALID_PARAM;
	}

	g_mode = mode;
	if (data_model_ver_bit & OCF_SH_100) {
		if (!rt_strcpy(data_model_ver, OCF_SH_100_VALUE)) {
			RT_LOG_E(TAG, "STRCPY_FAIL");
			goto ocf_init_failed;
		}
	}

	rt_random_init();

	if (OCF_OK != rt_mem_pool_init()) {
		ret = OCF_MEM_POOL_INIT_FAIL;
		RT_LOG_E(TAG, "OCF_MEM_POOL_INIT_FAIL");
		goto ocf_init_failed;
	}
	g_ocf_init_state |= RT_MEM_POOL_INIT;

	if (OCF_OK != rt_event_init()) {
		ret = OCF_EVENT_INIT_FAIL;
		RT_LOG_E(TAG, "OCF_EVENT_INIT_FAIL");
		goto ocf_init_failed;
	}
	g_ocf_init_state |= RT_EVENT_INIT;

	if (OCF_OK != rt_receive_queue_init()) {
		ret = OCF_RECEIVE_QUEUE_INIT_FAIL;
		RT_LOG_E(TAG, "OCF_RECEIVE_QUEUE_INIT_FAIL");
		goto ocf_init_failed;
	}
	g_ocf_init_state |= RT_RECEIVE_QUEUE_INIT;

	if (g_mode == OCF_CLIENT_SERVER || g_mode == OCF_CLIENT) {
		if (OCF_OK != rt_request_manager_init()) {
			ret = OCF_REQUEST_INIT_FAIL;
			RT_LOG_E(TAG, "OCF_REQUEST_INIT_FAIL");
			goto ocf_init_failed;
		}
		g_ocf_init_state |= RT_REQUEST_INIT;
	}

	if (OCF_OK != rt_resource_manager_init(manufacturer_name, data_model_ver)) {
		ret = OCF_RES_INIT_FAIL;
		RT_LOG_E(TAG, "OCF_RES_INIT_FAIL");
		goto ocf_init_failed;
	}
	g_ocf_init_state |= RT_RES_INIT;

	if (OCF_OK != rt_sec_init()) {
		ret = OCF_SECURITY_INIT_FAIL;
		RT_LOG_E(TAG, "OCF_SECURITY_INIT_FAIL");
		goto ocf_init_failed;
	}
	g_ocf_init_state |= RT_SECURITY_INIT;

	if (OCF_OK != rt_manager_init_periodic_process()) {
		ret = OCF_MANAGER_PERIODIC_PROCESS_INIT_FAIL;
		RT_LOG_E(TAG, "OCF_MANAGER_PERIODIC_PROCESS_INIT_FAIL");
		goto ocf_init_failed;
	}
	g_ocf_init_state |= RT_MANAGER_INIT_PERIODIC_PROCESS;

	if (OCF_OK != rt_coap_init(rt_receive_queue_request_enqueue, rt_receive_queue_response_enqueue)) {
		ret = OCF_COAP_INIT_FAIL;
		RT_LOG_E(TAG, "OCF_COAP_INIT_FAIL");
		goto ocf_init_failed;
	}
	g_ocf_init_state |= RT_COAP_INIT;

	return ret;

ocf_init_failed:
	ocf_terminate();
	return ret;
}

ocf_result_t ocf_terminate(void)
{
	if (g_ocf_init_state & RT_COAP_INIT) {
		rt_coap_terminate();
	}

	if (g_ocf_init_state & RT_MANAGER_INIT_PERIODIC_PROCESS) {
		rt_manager_terminate_periodic_process();
	}

	if (g_ocf_init_state & RT_SECURITY_INIT) {
		rt_sec_terminate();
	}

	if (g_mode == OCF_SERVER || g_mode == OCF_CLIENT_SERVER) {
		if (g_ocf_init_state & RT_RES_INIT) {
			rt_resource_manager_terminate();
		}
	}

	if (g_mode == OCF_CLIENT || g_mode == OCF_CLIENT_SERVER) {
		if (g_ocf_init_state & RT_REQUEST_INIT) {
			rt_request_manager_terminate();
		}
	}

	if (g_ocf_init_state & RT_RECEIVE_QUEUE_INIT) {
		rt_receive_queue_terminate();
	}

	if (g_ocf_init_state & RT_EVENT_INIT) {
		rt_event_terminate();
	}

	if (g_ocf_init_state & RT_MEM_POOL_INIT) {
		rt_mem_pool_terminate();
	}

	return OCF_OK;
}
