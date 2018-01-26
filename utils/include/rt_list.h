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

#ifndef __RT_OCF_LIST_H
#define __RT_OCF_LIST_H

#include <stddef.h>
#include <pthread.h>
#include "ocf_types.h"

#define RT_MEMBER_SIZE(type, member) sizeof(((type *)0)->member)
#define RT_MEMBER_ADDR(type, ptr, member) (offsetof(type, ptr) - offsetof(type, member))
#define RT_MEMBER_OFFSET(type, member) offsetof(type, member)
#define container_of(ptr, type, member) ((type*)((char*)ptr - offsetof(type, member)))

#ifndef NULL
#define NULL ((void*)0)
#endif

typedef void (*rt_list_release_item_cb)(void *item);

typedef struct _rt_node_s {
	struct _rt_node_s *prev;
	struct _rt_node_s *next;
} rt_node_s;

typedef struct _rt_list {
	uint32_t count;
	size_t struct_size;			// Size of struct to store
	uint32_t offset;					// Relative location of node in the struct
	pthread_mutex_t mutex;
	rt_node_s *head;
	rt_node_s *tail;
} rt_list_s;

void rt_list_init(rt_list_s *list, size_t struct_size, uint32_t offset);
void rt_list_insert(rt_list_s *list, rt_node_s *node);
void *rt_list_search(rt_list_s *list, uint32_t offset, int memb_size, void *key);
void *rt_list_delete(rt_list_s *list, uint32_t offset, int memb_size, void *key);
void *rt_list_delete_by_node(rt_list_s *list, rt_node_s *node);
void *rt_list_get_item(const rt_list_s *list, rt_node_s *node);
void rt_list_terminate(rt_list_s *list, rt_list_release_item_cb func);

#endif							/* __RT_OCF_LIST_H */
