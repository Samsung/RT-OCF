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

#ifndef __RT_OCF_QUEUE_H
#define __RT_OCF_QUEUE_H

#include "ocf_types.h"

typedef struct _rt_queue_element {
	void *data;
	struct _rt_queue_element *next;
} rt_queue_element_s;

typedef struct _rt_queue {
	int count;
	rt_queue_element_s *front;
	rt_queue_element_s *rear;
} rt_queue_s;

typedef void (*rt_queue_item_free_func)(void *);

void rt_queue_init(rt_queue_s *queue);
ocf_result_t rt_queue_push(rt_queue_s *queue, rt_queue_element_s *node);
rt_queue_element_s *rt_queue_pop(rt_queue_s *queue);
ocf_result_t rt_queue_remove_item(rt_queue_element_s *element, rt_queue_item_free_func free_func);
ocf_result_t rt_queue_terminate(rt_queue_s *queue, rt_queue_item_free_func free_func);

#endif							/* __RT_OCF_QUEUE_H */
