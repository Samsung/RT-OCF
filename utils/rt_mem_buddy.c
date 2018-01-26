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

#include <stdlib.h>
#include <stdbool.h>
#include "rt_mem_buddy.h"
#include "rt_utils.h"

#ifdef CONFIG_RT_OCF_BUDDY_MEM_SYS

#define TAG "RT_MEM_BUDDY"
#define ITEM_IS_LEFT 0
#define ITEM_IS_RIGHT 1

pthread_mutex_t g_mem_trace_mutex;

ocf_result_t rt_mem_buddy_init(mem_info_s *mInfo)
{
	RT_VERIFY_NON_NULL_RET(mInfo, TAG, "mInfo is NULL!", OCF_INVALID_PARAM);

	pthread_mutex_init(&g_mem_trace_mutex, NULL);

	static rt_list_s buddy_list;
	mInfo->buddy_list = &buddy_list;
	mInfo->occupied = 0;
	mInfo->external_frag_ratio = 0;

	mInfo->total = OCF_RT_MEM_POOL_SIZE;
	mInfo->address = (void *)malloc(OCF_RT_MEM_POOL_SIZE);
	mInfo->ptr = mInfo->address;

	mem_buddy_info_s *init_block = (mem_buddy_info_s *)malloc(sizeof(mem_buddy_info_s));
	if (init_block == NULL) {
		RT_LOG_E(TAG, "Memory Pool allocate fail");
		return OCF_MEM_POOL_INIT_FAIL;
	}
	init_block->address = mInfo->address;
	init_block->alloc_size = 0;
	init_block->block_size = OCF_RT_MEM_POOL_SIZE;

	RT_LOG_D(TAG, "[INIT] addr:%x\tblock size:%d", init_block->address, init_block->block_size);

	rt_list_init(mInfo->buddy_list, sizeof(mem_buddy_info_s), RT_MEMBER_OFFSET(mem_buddy_info_s, node));
	rt_list_insert(mInfo->buddy_list, &init_block->node);

	return OCF_OK;
}

void *rt_mem_buddy_alloc(mem_info_s *mInfo, uint32_t size)
{
	RT_VERIFY_NON_NULL_RET(mInfo, TAG, "mInfo is NULL!", NULL);
	if (size <= 0) {
		return NULL;
	}

	pthread_mutex_lock(&g_mem_trace_mutex);
	rt_list_s *buddy_list = mInfo->buddy_list;
	rt_node_s *itr = buddy_list->head;
	mem_buddy_info_s *var = NULL;
	void *alloc_ptr = NULL;

	do {
		// TODO: Currently, first-fit
		var = (mem_buddy_info_s *) rt_list_get_item(buddy_list, itr);
		// RT_LOG_D(TAG, "var_addr=0x%x, alloc_size=%d, block_size=%d", var->address, var->alloc_size, var->block_size);
		if (var == NULL || var->alloc_size > 0 || var->block_size < size) {
			continue;
		}
		// Possible to allocate memory block
		alloc_ptr = allocate_mem_block(mInfo, var, size);
		//RT_LOG_D(TAG, "[ALLOC] Success, Occupied=%d", mInfo->occupied);
		break;
	} while ((itr = itr->next));
	pthread_mutex_unlock(&g_mem_trace_mutex);

	return alloc_ptr;
}

// Insert block next to target
static void *split_block(mem_buddy_info_s *var)
{
	mem_buddy_info_s *empty_block = (mem_buddy_info_s *)malloc(sizeof(mem_buddy_info_s));
	empty_block->address = var->address + var->block_size / 2;
	empty_block->alloc_size = 0;
	empty_block->block_size = var->block_size / 2;
	//RT_LOG_D(TAG, "[SPLIT BLOCK] addr:%x\tblock size:%d", empty_block->address, empty_block->block_size);

	rt_node_s *empty_node = &empty_block->node;

	empty_node->prev = &var->node;
	empty_node->next = var->node.next;

	if (var->node.next != NULL) {
		var->node.next->prev = empty_node;
	}
	var->node.next = empty_node;
	var->block_size = var->block_size >> 1;

	return var->address;
}

static void *allocate_mem_block(mem_info_s *mInfo, mem_buddy_info_s *var, uint32_t size)
{
	void *alloc_ptr = NULL;
	uint32_t occupied_size = 0;

	if (var->block_size / 2 < size) {
		// Assign the current block
		alloc_ptr = var->address;
		occupied_size = var->block_size;
	} else {
		// Split the current block into two of the same size and then allocate.
		while (var->block_size >> 1 >= size) {
			alloc_ptr = split_block(var);
			occupied_size = var->block_size;
			mInfo->buddy_list->count++;
		}
	}
	var->alloc_size = size;
	RT_LOG_D(TAG, "[ASSIGN BLOCK] addr:%x, block size:%d, alloc size:%d", var->address, var->block_size, var->alloc_size);

	mInfo->current += size;
	mInfo->occupied += occupied_size;
	if (mInfo->current > mInfo->peak) {
		mInfo->peak = mInfo->current;
	}
	// print_buddy_list(mInfo);

	return alloc_ptr;
}

static uint32_t update_mem_info(mem_info_s *mInfo, mem_buddy_info_s *block_info)
{
	uint32_t return_size = block_info->alloc_size;
	mInfo->current -= block_info->alloc_size;
	mInfo->occupied -= block_info->block_size;
	RT_LOG_D(TAG, "[DEALLOCATION] dealloc_size=%d, occupied=%d", block_info->alloc_size, mInfo->occupied);
	block_info->alloc_size = 0;
	return return_size;
}

uint32_t rt_mem_buddy_free(mem_info_s *mInfo, void *ptr)
{
	RT_VERIFY_NON_NULL_RET(mInfo, TAG, "mInfo is NULL!", 0);
	RT_VERIFY_NON_NULL_RET(ptr, TAG, "prt is NULL!", 0);

	pthread_mutex_lock(&g_mem_trace_mutex);
	rt_list_s *buddy_list = mInfo->buddy_list;
	mem_buddy_info_s *mem_block_info = rt_list_search(buddy_list, RT_MEMBER_OFFSET(mem_buddy_info_s, address), RT_MEMBER_SIZE(mem_buddy_info_s, address), &ptr);

	uint32_t return_size = 0;
	if (mem_block_info == NULL) {
		RT_LOG_E(TAG, "mem_block_info is not found");
		pthread_mutex_unlock(&g_mem_trace_mutex);
		return return_size;
	}

	return_size = update_mem_info(mInfo, mem_block_info);

	merge_block(mInfo, mem_block_info);
	pthread_mutex_unlock(&g_mem_trace_mutex);
//  print_buddy_list(mInfo);
	return return_size;
}

float rt_mem_buddy_get_external_frag(mem_info_s *mInfo)
{
	RT_VERIFY_NON_NULL_RET(mInfo, TAG, "mInfo is NULL!", 0);

	rt_list_s *buddy_list = mInfo->buddy_list;
	rt_node_s *itr = buddy_list->head;
	mem_buddy_info_s *var = NULL;
	int max_block_size = 0;
	do {
		var = (mem_buddy_info_s *) rt_list_get_item(buddy_list, itr);
		if (var == NULL || var->alloc_size > 0) {
			continue;
		}
		if (var->block_size < max_block_size) {
			continue;
		}
		max_block_size = var->block_size;
	} while ((itr = itr->next) != NULL);

	if (OCF_RT_MEM_POOL_SIZE - mInfo->current == 0) {
		return 0.0f;
	}
	return 1 - (max_block_size / (float)(OCF_RT_MEM_POOL_SIZE - mInfo->current));
}

static uint8_t check_direction(uint32_t pos, uint32_t total, uint32_t block_size)
{
	uint32_t left = 0, right = total;
	uint32_t pivot;
	uint8_t direction = ITEM_IS_LEFT;	// left = 0, right = 1
	uint32_t curr_len = right - left;

	while (1) {
		curr_len = curr_len >> 1;
		pivot = (right + left) >> 1;

		if (pos >= pivot) {
			left = pivot;
			direction = ITEM_IS_RIGHT;
		} else {
			right = pivot;
			direction = ITEM_IS_LEFT;
		}

		if (curr_len <= block_size) {
			return direction;
		}
	}

	return ITEM_IS_LEFT;
}

static bool is_empty_sibling(mem_buddy_info_s *target_item, mem_buddy_info_s *var)
{
	return (target_item->alloc_size == 0 && target_item->block_size == var->block_size);
}

static mem_buddy_info_s *merge_right_block(rt_list_s *list, mem_buddy_info_s *var)
{
	rt_node_s *target_node = var->node.next;
	if (target_node != NULL) {
		mem_buddy_info_s *target_item = (mem_buddy_info_s *) rt_list_get_item(list, target_node);
		if (is_empty_sibling(target_item, var)) {
			var->block_size = var->block_size << 1;
			var->node.next = target_item->node.next;
			if (target_item->node.next != NULL) {
				rt_node_s *next_next = target_item->node.next;
				next_next->prev = &var->node;
			}

			RT_LOG_D(TAG, "[MERGE RIGHT] block_size=%d", var->block_size);

			free(target_item);
			return var;
		}
	}
	return NULL;
}

static mem_buddy_info_s *merge_left_block(rt_list_s *list, mem_buddy_info_s *var)
{
	rt_node_s *target_node = var->node.prev;
	if (target_node != NULL) {
		mem_buddy_info_s *target_item = (mem_buddy_info_s *) rt_list_get_item(list, target_node);
		if (is_empty_sibling(target_item, var)) {
			var->address = target_item->address;
			var->block_size = var->block_size << 1;
			var->node.prev = target_item->node.prev;
			if (target_item->node.prev != NULL) {
				rt_node_s *prev_prev = target_item->node.prev;
				prev_prev->next = &var->node;
			} else {
				list->head = &var->node;
			}

			RT_LOG_D(TAG, "[MERGE LEFT] block_size=%d", var->block_size);

			free(target_item);
			return var;
		}
	}
	return NULL;
}

static void merge_block(mem_info_s *mInfo, mem_buddy_info_s *mem_block_info)
{
	do {
		uint8_t direction = check_direction(mem_block_info->address - mInfo->address, mInfo->total, mem_block_info->block_size);
		if (direction == ITEM_IS_LEFT) {
			mem_block_info = merge_right_block(mInfo->buddy_list, mem_block_info);
		} else {
			mem_block_info = merge_left_block(mInfo->buddy_list, mem_block_info);
		}
		if (mem_block_info != NULL) {
			mInfo->buddy_list->count--;
		}
	} while (mem_block_info != NULL);
}

int rt_mem_buddy_terminate(mem_info_s *mInfo)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	unsigned int ret = 0;
	rt_node_s *itr;

	if (mInfo->buddy_list != NULL) {
		itr = mInfo->buddy_list->head;
		ret = mInfo->current;
		while (itr) {
			mem_buddy_info_s *var = (mem_buddy_info_s *) rt_list_get_item(mInfo->buddy_list, itr);
			if (var->alloc_size > 0) {
				rt_mem_buddy_free(mInfo, var->address);
			}
			itr = itr->next;
		}
	}
	// Release init_block
	itr = mInfo->buddy_list->head;
	mem_buddy_info_s *var = (mem_buddy_info_s *) rt_list_delete_by_node(mInfo->buddy_list, itr);
	free(var);

	RT_LOG_D(TAG, "OUT : %s", __func__);

	return ret;
}

static void print_buddy_list(mem_info_s *mInfo)
{
	rt_list_s *buddy_list = mInfo->buddy_list;
	rt_node_s *itr = buddy_list->head;
	mem_buddy_info_s *var = NULL;

	while (itr) {
		var = (mem_buddy_info_s *) rt_list_get_item(buddy_list, itr);
		RT_LOG_D(TAG, "(Alloc: %d, Block: %d @ %x) ->", var->alloc_size, var->block_size, var->address);
		itr = itr->next;
	}

	RT_LOG_D(TAG, "\tBuddy_list_ptr : 0x%x", mInfo->buddy_list);
}
#endif
