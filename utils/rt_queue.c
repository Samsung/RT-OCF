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
#include <string.h>

#include "rt_queue.h"
#include "rt_mem.h"
#include "rt_logger.h"
#include "rt_utils.h"

#define TAG "RT_QUEUE"

void rt_queue_init(rt_queue_s *queue)
{
	queue->count = 0;
	queue->front = NULL;
	queue->rear = NULL;
}

ocf_result_t rt_queue_push(rt_queue_s *queue, rt_queue_element_s *node)
{
	RT_VERIFY_NON_NULL_RET(queue, TAG, "queue is NULL", OCF_INVALID_PARAM);

	node->next = NULL;

	while (1) {
		if (queue->front == NULL && queue->rear == NULL) {
			rt_queue_element_s *front = queue->front;
			rt_queue_element_s *rear = queue->rear;

			if (__sync_bool_compare_and_swap(&queue->front, front, node)) {
				__sync_bool_compare_and_swap(&queue->rear, rear, node);
				break;
			}
		} else {
			rt_queue_element_s *rear = queue->rear;
			rt_queue_element_s *next = rear->next;

			if (NULL == next) {
				if (__sync_bool_compare_and_swap(&rear->next, next, node)) {
					__sync_bool_compare_and_swap(&queue->rear, rear, node);
					break;
				}
			} else {
				__sync_bool_compare_and_swap(&queue->rear, rear, next);
			}

		}
	}

	__sync_add_and_fetch(&queue->count, 1);

	return OCF_OK;
}

rt_queue_element_s *rt_queue_pop(rt_queue_s *queue)
{
	RT_VERIFY_NON_NULL_RET(queue, TAG, "queue is NULL", NULL);

	rt_queue_element_s *output = NULL;
	while (1) {
		rt_queue_element_s *front = queue->front;
		rt_queue_element_s *rear = queue->rear;
		output = queue->front;

		if (queue->front == NULL && queue->rear == NULL) {	//nothing
			return NULL;
		}
		
		if (queue->front == NULL || queue->rear == NULL) {
			continue;
		}

		if (queue->front == queue->rear && queue->count == 1) {
			if (__sync_bool_compare_and_swap(&queue->front, front, NULL)) {
				__sync_bool_compare_and_swap(&queue->rear, rear, NULL);
				break;
			}
		} else {
			rt_queue_element_s *next = front->next;
			if (front == queue->front) {
				if (__sync_bool_compare_and_swap(&queue->front, front, next)) {
					break;
				}
			}
		}
	}

	RT_VERIFY_NON_NULL_RET(output, TAG, "output is NULL", NULL);

	output->next = NULL;
	__sync_sub_and_fetch(&queue->count, 1);

	return output;
}

ocf_result_t rt_queue_remove_item(rt_queue_element_s *element, rt_queue_item_free_func free_func)
{
	RT_VERIFY_NON_NULL_RET(element, TAG, "element is NULL", OCF_INVALID_PARAM);

	if (free_func) {
		free_func(element->data);
	}
	rt_mem_free(element->data);
	rt_mem_free(element);

	return OCF_OK;
}

ocf_result_t rt_queue_terminate(rt_queue_s *queue, rt_queue_item_free_func free_func)
{
	RT_VERIFY_NON_NULL_RET(queue, TAG, "queue is NULL", OCF_INVALID_PARAM);

	rt_queue_element_s *element;
	while ((element = rt_queue_pop(queue))) {
		rt_queue_remove_item(element, free_func);
	}

	queue->front = queue->rear = NULL;

	return OCF_OK;
}
