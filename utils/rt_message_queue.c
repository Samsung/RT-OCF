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

#include "rt_message_queue.h"
#include "rt_mem.h"
#include "rt_logger.h"
#include "rt_utils.h"

#define TAG "RT_MESSAGE_QUEUE"

#define RT_MALLOC_WITH_ERR_RET(tag, x, type) do { \
	x = (type *)rt_mem_alloc(sizeof(type)); \
	RT_VERIFY_NON_NULL_RET(x, tag, #x, OCF_MEM_FULL); \
} while (0)

static void *rt_message_queue_runner(void *data);

ocf_result_t rt_message_queue_init(rt_message_queue_s *message_queue, msg_queue_running_func func, rt_queue_item_free_func free_func, const char *name)
{
	RT_VERIFY_NON_NULL_RET(message_queue, TAG, "message_queue", OCF_INVALID_PARAM);
	RT_VERIFY_NON_NULL_RET(func, TAG, "func", OCF_INVALID_PARAM);
	RT_LOG_D(TAG, "%s IN", __func__);

	if (!message_queue->terminate && message_queue->thread_info.thread) {
		RT_LOG_E(TAG, "Already rt_message_queue_init");
		return OCF_ALREADY_INIT;
	}

	message_queue->terminate = 0;
	message_queue->func = func;
	message_queue->free_func = free_func;

	RT_MALLOC_WITH_ERR_RET(TAG, message_queue->mutex, pthread_mutex_t);
	pthread_mutex_init(message_queue->mutex, NULL);
	RT_MALLOC_WITH_ERR_RET(TAG, message_queue->cond, pthread_cond_t);
	pthread_cond_init(message_queue->cond, NULL);

	ocf_result_t ret = OCF_ERROR;
	if (OCF_OK != (ret = rt_thread_init(&message_queue->thread_info, rt_message_queue_runner, name, 0, message_queue))) {
		RT_LOG_E(TAG, "rt_thread_init failed!");
		return ret;
	}

	rt_queue_init(&message_queue->queue);

	RT_LOG_D(TAG, "%s OUT", __func__);
	return OCF_OK;
}

ocf_result_t rt_message_queue_enqueue(rt_message_queue_s *message_queue, void *data)
{
	RT_VERIFY_NON_NULL_RET(message_queue, TAG, "message_queue", OCF_INVALID_PARAM);
	RT_VERIFY_NON_NULL_RET(data, TAG, "data", OCF_INVALID_PARAM);
	RT_LOG_D(TAG, "%s IN", __func__);

	if (message_queue->terminate) {
		RT_LOG_E(TAG, "message queue is not initialized!");
		return OCF_NOT_INITIALIZE;
	}

	rt_queue_element_s *element;
	RT_MALLOC_WITH_ERR_RET(TAG, element, rt_queue_element_s);
	element->data = data;

	rt_queue_push(&message_queue->queue, element);

	pthread_mutex_lock(message_queue->mutex);
	pthread_cond_signal(message_queue->cond);
	pthread_mutex_unlock(message_queue->mutex);

	return OCF_OK;
}

static void *rt_message_queue_runner(void *data)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	rt_message_queue_s *message_queue = (rt_message_queue_s *) data;

	while (!message_queue->terminate) {

		pthread_mutex_lock(message_queue->mutex);
		if (!message_queue->terminate && message_queue->queue.count <= 0) {
			RT_LOG_D(TAG, "Wait.");
			pthread_cond_wait(message_queue->cond, message_queue->mutex);
			RT_LOG_D(TAG, "Wake up.");
		}

		if (message_queue->terminate) {
			pthread_mutex_unlock(message_queue->mutex);
			break;
		}
		pthread_mutex_unlock(message_queue->mutex);

		rt_queue_element_s *element = rt_queue_pop(&message_queue->queue);
		if (!element) {
			continue;
		}

		message_queue->func(element->data);

		rt_queue_remove_item(element, message_queue->free_func);
	}

	RT_LOG_D(TAG, "%s OUT", __func__);

	return NULL;
}

static void rt_message_queue_thread_terminate_func(void *user_data)
{
	rt_message_queue_s *message_queue = (rt_message_queue_s *) user_data;

	pthread_mutex_lock(message_queue->mutex);
	message_queue->terminate = 1;
	pthread_cond_signal(message_queue->cond);
	pthread_mutex_unlock(message_queue->mutex);
}

void rt_message_queue_terminate(rt_message_queue_s *message_queue)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	if (!message_queue->terminate && message_queue->thread_info.thread) {
		rt_thread_terminate(&message_queue->thread_info, rt_message_queue_thread_terminate_func, message_queue);
	}

	if (message_queue->mutex) {
		pthread_mutex_destroy(message_queue->mutex);
		rt_mem_free(message_queue->mutex);
		message_queue->mutex = NULL;
	}

	if (message_queue->cond) {
		pthread_cond_destroy(message_queue->cond);
		rt_mem_free(message_queue->cond);
		message_queue->cond = NULL;
	}

	rt_queue_terminate(&message_queue->queue, message_queue->free_func);

	RT_LOG_D(TAG, "%s OUT", __func__);
}
