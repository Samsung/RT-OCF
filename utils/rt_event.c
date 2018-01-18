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

#include <pthread.h>
#include <errno.h>
#include <sys/time.h>
#include "rt_event.h"
#include "rt_mem.h"
#include "rt_logger.h"
#include "rt_utils.h"

#define TAG "RT_EVT"

static pthread_mutex_t *g_event_mutex = NULL;
static pthread_cond_t *g_event_cond = NULL;
static uint8_t g_event_semaphore = 0;

ocf_result_t rt_event_init(void)
{
	RT_LOG_D(TAG, "rt_event_init IN");

	if (g_event_mutex || g_event_cond) {
		RT_LOG_E(TAG, "rt_event is already init!");
		return OCF_ALREADY_INIT;
	}

	g_event_mutex = (pthread_mutex_t *)rt_mem_alloc(sizeof(pthread_mutex_t));
	RT_VERIFY_NON_NULL_RET(g_event_mutex, TAG, "g_event_mutex", OCF_MEM_FULL);
	g_event_cond = (pthread_cond_t *)rt_mem_alloc(sizeof(pthread_cond_t));
	RT_VERIFY_NON_NULL_RET(g_event_cond, TAG, "g_event_cond", OCF_MEM_FULL);

	pthread_mutex_init(g_event_mutex, NULL);
	pthread_cond_init(g_event_cond, NULL);

	pthread_mutex_lock(g_event_mutex);
	g_event_semaphore = 0;
	pthread_mutex_unlock(g_event_mutex);

	//TODO: check error;
	RT_LOG_D(TAG, "rt_event_init OUT");
	return OCF_OK;
}

ocf_result_t rt_event_terminate(void)
{
	RT_VERIFY_NON_NULL_RET(g_event_mutex, TAG, "g_event_mutex isn't initialized", OCF_ERROR);
	RT_VERIFY_NON_NULL_RET(g_event_cond, TAG, "g_event_cond isn't initialized", OCF_ERROR);
	RT_LOG_D(TAG, "rt_event_terminate IN");

	rt_event_set_signal();

	pthread_mutex_lock(g_event_mutex);
	g_event_semaphore = 0;
	pthread_mutex_unlock(g_event_mutex);

	pthread_cond_destroy(g_event_cond);
	pthread_mutex_destroy(g_event_mutex);

	rt_mem_free(g_event_mutex);
	g_event_mutex = NULL;
	rt_mem_free(g_event_cond);
	g_event_cond = NULL;

	// TODO:[EBUSY]
	RT_LOG_D(TAG, "rt_event_terminate OUT");
	return OCF_OK;
}

#define GET_WAKEUP_SEC(arg)  (arg / CLOCKS_PER_SEC)
#define GET_WAKEUP_NANO_SEC(arg) (((arg % CLOCKS_PER_SEC) * 1000000000) / CLOCKS_PER_SEC)

int rt_event_timedwait(const rt_clock_time_t wakeup_time)
{
	RT_VERIFY_NON_NULL_RET(g_event_mutex, TAG, "g_event_mutex", -1);
	RT_VERIFY_NON_NULL_RET(g_event_cond, TAG, "g_event_cond", -1);

	struct timespec time_to_wait;
	int rc = 0;
	time_to_wait.tv_sec = GET_WAKEUP_SEC(wakeup_time);
	time_to_wait.tv_nsec = GET_WAKEUP_NANO_SEC(wakeup_time);

	pthread_mutex_lock(g_event_mutex);
	if (g_event_semaphore == 0) {
		rc = pthread_cond_timedwait(g_event_cond, g_event_mutex, &time_to_wait);
	}
	g_event_semaphore = 0;	//TODO: 0 or g_event_semaphore - 1
	pthread_mutex_unlock(g_event_mutex);

	return rc;
}

int rt_event_wait(void)
{
	RT_VERIFY_NON_NULL_RET(g_event_mutex, TAG, "g_event_mutex", -1);
	RT_VERIFY_NON_NULL_RET(g_event_cond, TAG, "g_event_cond", -1);

	int rc = 0;
	pthread_mutex_lock(g_event_mutex);
	if (g_event_semaphore == 0) {
		rc = pthread_cond_wait(g_event_cond, g_event_mutex);
	}
	g_event_semaphore = 0;	//TODO: 0 or g_event_semaphore - 1
	pthread_mutex_unlock(g_event_mutex);

	return rc;
}

int rt_event_set_signal(void)
{
	RT_VERIFY_NON_NULL_RET(g_event_mutex, TAG, "g_event_mutex", -1);
	RT_VERIFY_NON_NULL_RET(g_event_cond, TAG, "g_event_cond", -1);

	int rc = 0;
	pthread_mutex_lock(g_event_mutex);
	rc = pthread_cond_signal(g_event_cond);
	g_event_semaphore++;
	RT_LOG_D(TAG, "==>event signal set!");
	pthread_mutex_unlock(g_event_mutex);
	return rc;
}
