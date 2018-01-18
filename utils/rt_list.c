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

#include "rt_list.h"
#include "rt_mem.h"
#include "rt_logger.h"
#include "rt_utils.h"
#include <pthread.h>

#define TAG "RT_LIST"

void rt_list_init(rt_list_s *list, size_t struct_size, uint32_t offset)
{
	RT_VERIFY_NON_NULL_VOID(list, TAG, "list is null");

	pthread_mutex_init(&list->mutex, NULL);

	pthread_mutex_lock(&list->mutex);
	list->count = 0;
	list->struct_size = struct_size;
	list->offset = offset;
	list->head = NULL;
	list->tail = NULL;
	pthread_mutex_unlock(&list->mutex);
}

void rt_list_insert(rt_list_s *list, rt_node_s *node)
{
	node->next = NULL;
	node->prev = list->tail;

	while (1) {
		if (list->head == NULL && list->tail == NULL) {
			rt_node_s *head = list->head;
			rt_node_s *tail = list->tail;

			if (__sync_bool_compare_and_swap(&list->head, head, node)) {
				__sync_bool_compare_and_swap(&list->tail, tail, node);
				break;
			}
		} else {
			rt_node_s *tail = list->tail;
			rt_node_s *next = tail->next;

			if (NULL == next) {
				if (__sync_bool_compare_and_swap(&tail->next, next, node)) {
					__sync_bool_compare_and_swap(&list->tail, tail, node);
					break;
				}
			} else {
				__sync_bool_compare_and_swap(&list->tail, tail, next);
			}

		}
	}

	__sync_add_and_fetch(&list->count, 1);
}

static void delete_node(rt_list_s *list, rt_node_s *node)
{
	while (1) {
		rt_node_s *prev = node->prev;
		rt_node_s *next = node->next;
		if (prev == NULL && next == NULL) {
			rt_node_s *head = list->head;
			rt_node_s *tail = list->tail;
			if (__sync_bool_compare_and_swap(&list->head, head, NULL)) {
				__sync_bool_compare_and_swap(&list->tail, tail, NULL);
				break;
			}
		} else if (prev == NULL) {	//When Head
			rt_node_s *next_prev = next->prev;
			rt_node_s *head = list->head;
			if (__sync_bool_compare_and_swap(&next->prev, next_prev, NULL)) {
				__sync_bool_compare_and_swap(&list->head, head, node->next);
				break;
			}
		} else if (next == NULL) {	//When Tail
			rt_node_s *prev_next = prev->next;
			rt_node_s *tail = list->tail;
			if (__sync_bool_compare_and_swap(&prev->next, prev_next, NULL)) {
				__sync_bool_compare_and_swap(&list->tail, tail, node->prev);
				break;
			}
		} else {
			rt_node_s *prev_next = prev->next;
			rt_node_s *next_prev = next->prev;
			if (__sync_bool_compare_and_swap(&prev->next, prev_next, node->next)) {
				__sync_bool_compare_and_swap(&next->prev, next_prev, node->prev);
				break;
			}
		}
	}
	__sync_add_and_fetch(&list->count, -1);
}

void *rt_list_delete(rt_list_s *list, uint32_t offset, int memb_size, void *key)
{
	RT_VERIFY_NON_NULL_RET(list, TAG, "list is null", NULL);
	void *item = rt_list_search(list, offset, memb_size, key);
	if (item == NULL) {
		return NULL;
	}
	rt_node_s *node = (rt_node_s *)((char *)item + list->offset);
	delete_node(list, node);
	return item;
}

void *rt_list_delete_by_node(rt_list_s *list, rt_node_s *node)
{
	if (list->count <= 0) {
		return NULL;
	}
	delete_node(list, node);
	return rt_list_get_item(list, node);
}

void *rt_list_search(rt_list_s *list, uint32_t offset, int memb_size, void *key)
{
	RT_VERIFY_NON_NULL_RET(list, TAG, "list is null", NULL);

	rt_node_s *tmp = list->head;

	void *data;
	int i;
	while (tmp != NULL) {
		data = (void *)((char *)tmp - list->offset);
		for (i = 0; i < memb_size; i++) {
			if (*((char *)data + offset + i) != *((char *)key + i)) {
				break;
			}
		}
		if (i == memb_size) {
			return rt_list_get_item(list, tmp);
		}
		tmp = tmp->next;
	}

	return NULL;
}

void *rt_list_get_item(const rt_list_s *list, rt_node_s *node)
{
	RT_VERIFY_NON_NULL_RET(list, TAG, "list is null", NULL);
	RT_VERIFY_NON_NULL_RET(node, TAG, "node is null", NULL);
	return (void *)((char *)node - list->offset);
}

void rt_list_terminate(rt_list_s *list, rt_list_release_item_cb func)
{
	RT_VERIFY_NON_NULL_VOID(list, TAG, "list is null");
	rt_node_s *node = list->head;
	while (node) {
		void *var = rt_list_delete_by_node(list, node);
		if (func) {
			func(var);
		}
		rt_mem_free(var);
		node = list->head;
	}

	pthread_mutex_destroy(&list->mutex);
}
