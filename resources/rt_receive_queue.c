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

#include "rt_receive_queue.h"
#include "rt_message_queue.h"
#include "rt_logger.h"
#include "rt_utils.h"
#include "rt_mem.h"

#define TAG "RECV_QUEUE"

static rt_message_queue_s receive_queue;

static receive_callback g_request_callback = NULL;
static receive_callback g_response_callback = NULL;
static pthread_mutex_t g_receive_callback_mutex;

static void rt_receive_queue_runner(void *data)
{
	rt_receive_queue_item_s *item = (rt_receive_queue_item_s *) data;
	RT_LOG_D(TAG, "%s", __func__);

	pthread_mutex_lock(&g_receive_callback_mutex);
	if (item->type == RT_REQUEST) {
		if (g_request_callback) {
			g_request_callback(item->packet, &item->endpoint);
		}
	} else if (item->type == RT_RESPONSE) {
		if (g_response_callback) {
			g_response_callback(item->packet, &item->endpoint);
		}
	}
	pthread_mutex_unlock(&g_receive_callback_mutex);
}

static void rt_receive_queue_item_free_func(void *item)
{
	rt_receive_queue_item_s *data = (rt_receive_queue_item_s *) item;
	if (data->packet) {
		rt_data_free_item(data->packet);
	}
}

ocf_result_t rt_receive_queue_init(void)
{
	pthread_mutex_init(&g_receive_callback_mutex, NULL);
	return rt_message_queue_init(&receive_queue, rt_receive_queue_runner, rt_receive_queue_item_free_func, "receive_queue");
}

void rt_receive_queue_terminate(void)
{
	pthread_mutex_lock(&g_receive_callback_mutex);
	g_request_callback = NULL;
	g_response_callback = NULL;
	pthread_mutex_unlock(&g_receive_callback_mutex);

	pthread_mutex_destroy(&g_receive_callback_mutex);

	rt_message_queue_terminate(&receive_queue);
}

static ocf_result_t rt_receive_queue_enqueue(rt_recv_type_t type, rt_data_s *packet, const ocf_endpoint_s *endpoint)
{
	RT_VERIFY_NON_NULL_RET(packet, TAG, "packet is null", OCF_INVALID_PARAM);
	RT_VERIFY_NON_NULL_RET(endpoint, TAG, "endpoint is null", OCF_INVALID_PARAM);

	rt_receive_queue_item_s *item = (rt_receive_queue_item_s *) rt_mem_alloc(sizeof(rt_receive_queue_item_s));
	RT_VERIFY_NON_NULL_RET(item, TAG, "item", OCF_MEM_FULL);

	item->packet = packet;
	rt_mem_cpy(&item->endpoint, endpoint, sizeof(ocf_endpoint_s));
	item->type = type;
	ocf_result_t ret = rt_message_queue_enqueue(&receive_queue, (void *)item);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_message_queue_enqueue failed!");
		rt_mem_free(item);
		return ret;
	}
	return OCF_OK;
}

ocf_result_t rt_receive_queue_request_enqueue(rt_data_s *packet, const ocf_endpoint_s *endpoint)
{
	return rt_receive_queue_enqueue(RT_REQUEST, packet, endpoint);
}

ocf_result_t rt_receive_queue_response_enqueue(rt_data_s *packet, const ocf_endpoint_s *endpoint)
{
	return rt_receive_queue_enqueue(RT_RESPONSE, packet, endpoint);
}

ocf_result_t rt_receive_queue_set_request_callback(receive_callback callback)
{
	RT_VERIFY_NON_NULL_RET(callback, TAG, "callback", OCF_INVALID_PARAM);
	pthread_mutex_lock(&g_receive_callback_mutex);
	g_request_callback = callback;
	pthread_mutex_unlock(&g_receive_callback_mutex);
	return OCF_OK;
}

ocf_result_t rt_receive_queue_set_response_callback(receive_callback callback)
{
	RT_VERIFY_NON_NULL_RET(callback, TAG, "callback", OCF_INVALID_PARAM);
	pthread_mutex_lock(&g_receive_callback_mutex);
	g_response_callback = callback;
	pthread_mutex_unlock(&g_receive_callback_mutex);
	return OCF_OK;
}
