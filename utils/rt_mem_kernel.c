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

#include "rt_mem_kernel.h"

#include <stdlib.h>
#include "rt_logger.h"

#ifdef CONFIG_RT_OCF_KERNEL_MEM_SYS

#define TAG "RT_MEM_KERNEL"

pthread_mutex_t g_mem_trace_mutex;

ocf_result_t rt_mem_kernel_init(mem_info_s *mInfo)
{
	static rt_list_s list;
	mInfo->kernel_list = &list;
	rt_list_init(mInfo->kernel_list, sizeof(mem_assign_info_s), RT_MEMBER_OFFSET(mem_assign_info_s, node));

	pthread_mutex_init(&g_mem_trace_mutex, NULL);

	return OCF_OK;
}

void *rt_mem_kernel_alloc(mem_info_s *mInfo, uint32_t size)
{
	mem_assign_info_s *item = (mem_assign_info_s *)malloc(sizeof(mem_assign_info_s));
	if (!item) {
		RT_LOG_E(TAG, "Memory allocation failed.");
		return NULL;
	}
	item->size = size;
	item->address = (void *)malloc(size);
	pthread_mutex_lock(&g_mem_trace_mutex);
	rt_list_insert(mInfo->kernel_list, &item->node);
	mInfo->current += size;
	if (mInfo->current > mInfo->peak) {
		mInfo->peak = mInfo->current;
	}
	pthread_mutex_unlock(&g_mem_trace_mutex);
	return item->address;
}

unsigned int rt_mem_kernel_free(mem_info_s *mInfo, void *ptr)
{
	int size = 0;
	mem_assign_info_s *item;
	item = (mem_assign_info_s *) rt_list_delete(mInfo->kernel_list, RT_MEMBER_OFFSET(mem_assign_info_s, address), RT_MEMBER_SIZE(mem_assign_info_s, address), &ptr);
	if (item != NULL) {
		pthread_mutex_lock(&g_mem_trace_mutex);
		mInfo->current = mInfo->current - item->size;
		pthread_mutex_unlock(&g_mem_trace_mutex);
		size = item->size;
		free(item);
	}

	free(ptr);

	return size;
}

int rt_mem_kernel_terminate(mem_info_s *mInfo)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	unsigned int ret = 0;
	rt_node_s *itr;
	if (mInfo->kernel_list != NULL) {
		itr = mInfo->kernel_list->head;
		ret = mInfo->current;
		while (itr) {
			mem_assign_info_s *var = (mem_assign_info_s *) rt_list_get_item(mInfo->kernel_list, itr);
			RT_LOG_D(TAG, "leaked : %6d", var->size);
			itr = itr->next;
			rt_mem_kernel_free(mInfo, var->address);
		}
	}
	RT_LOG_D(TAG, "OUT : %s", __func__);

	return ret;
}
#endif
