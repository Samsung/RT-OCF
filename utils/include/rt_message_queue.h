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

#ifndef __IOTIVITY_RT_MESSAGE_QUEUE_H
#define __IOTIVITY_RT_MESSAGE_QUEUE_H

#include <stdint.h>

#include "rt_thread.h"
#include "rt_queue.h"
#include "ocf_types.h"

typedef void (*msg_queue_running_func)(void *);

typedef struct {
	rt_thread_s thread_info;
	pthread_mutex_t *mutex;
	pthread_cond_t *cond;
	msg_queue_running_func func;
	rt_queue_item_free_func free_func;
	rt_queue_s queue;
	uint8_t terminate;
} rt_message_queue_s;

ocf_result_t rt_message_queue_init(rt_message_queue_s *message_queue, msg_queue_running_func func, rt_queue_item_free_func free_func, const char *name);
ocf_result_t rt_message_queue_enqueue(rt_message_queue_s *message_queue, void *data);
void rt_message_queue_terminate(rt_message_queue_s *message_queue);
#endif							/* __IOTIVITY_RT_MESSAGE_QUEUE_H */
