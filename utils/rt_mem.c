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
#include <stdlib.h>
#include <stddef.h>
#include <string.h>
#include "rt_mem.h"
#include "rt_logger.h"
#include "rt_utils.h"

#if defined(CONFIG_RT_OCF_KERNEL_MEM_SYS)
#include "rt_mem_kernel.h"
#elif defined(CONFIG_RT_OCF_BUDDY_MEM_SYS)
#include "rt_mem_buddy.h"
#endif

#define TAG	"RT_MEM"

static mem_info_s mInfo = {
	0,
};

#ifdef CONFIG_RT_OCF_TRACE_MEMORY
static void rt_mem_pool_init_log(void);
static void rt_mem_append_log(const char *func, int size, uint8_t type, void *address);
static void rt_mem_terminate_log(void);
#endif

ocf_result_t rt_mem_pool_init(void)
{
	RT_LOG_D(TAG, "IN %s", __func__);

#ifdef CONFIG_RT_OCF_TRACE_MEMORY
	rt_mem_pool_init_log();
#endif							/* CONFIG_RT_OCF_TRACE_MEMORY */

	ocf_result_t ret = OCF_OK;
	mInfo.current = 0;
	mInfo.peak = 0;
	mInfo.total = OCF_RT_MEM_POOL_SIZE;

#if defined(CONFIG_RT_OCF_KERNEL_MEM_SYS)
	ret = rt_mem_kernel_init(&mInfo);
#elif defined(CONFIG_RT_OCF_BUDDY_MEM_SYS)
	ret = rt_mem_buddy_init(&mInfo);
#endif
	RT_LOG_D(TAG, "OUT %s", __func__);
	return ret;
}

#ifdef CONFIG_RT_OCF_TRACE_MEMORY
void *__rt_mem_alloc(int size, const char *func)
#else
void *__rt_mem_alloc(int size)
#endif
{
	void *alloc_addr = NULL;

	if (size <= 0) {
		RT_LOG_E(TAG, "size should bigger than 0.");
		return NULL;
	}
#if defined(CONFIG_RT_OCF_KERNEL_MEM_SYS)
	alloc_addr = rt_mem_kernel_alloc(&mInfo, size);
#elif defined(CONFIG_RT_OCF_BUDDY_MEM_SYS)
	alloc_addr = rt_mem_buddy_alloc(&mInfo, size);
#endif							/* CONFIG_RT_OCF_BUDDY_MEM_SYS */

#ifdef CONFIG_RT_OCF_TRACE_MEMORY
	rt_mem_append_log(func, size, 1, alloc_addr);
#endif							/* CONFIG_RT_OCF_TRACE_MEMORY */
	if (!alloc_addr) {
		RT_LOG_E(TAG, "Could not alloc memory. alloc_addr = %d", alloc_addr);
		return NULL;
	}
	memset(alloc_addr, 0, size);
	return alloc_addr;
}

static int get_mem_size(void *ptr)
{
#if defined(CONFIG_RT_OCF_KERNEL_MEM_SYS)
	rt_node_s *itr = mInfo.kernel_list->head;
	while (itr) {
		mem_assign_info_s *item = (mem_assign_info_s *) rt_list_get_item(mInfo.kernel_list, itr);
		if (item->address == ptr && item->size > 0) {
			return item->size;
		}
		itr = itr->next;
	}
	return -1;
#elif defined(CONFIG_RT_OCF_BUDDY_MEM_SYS)
	return -1;
#endif
}

void *rt_mem_realloc(void *ptr, int resize)
{
	RT_VERIFY_NON_NULL_RET(ptr, TAG, "ptr is NULL", NULL);

	int size = -1;
	void *temp = ptr;
#if defined(CONFIG_RT_OCF_KERNEL_MEM_SYS)
	size = get_mem_size(ptr);
	if (size <= 0) {
		RT_LOG_E(TAG, "ptr is not an allocated memory");
		return NULL;
	}

	if (size == resize) {
		return ptr;
	}

	temp = rt_mem_alloc(resize);
	RT_VERIFY_NON_NULL_RET(temp, TAG, "Memory is full", NULL);

	memcpy(temp, ptr, (size > resize ? resize : size));

	rt_mem_free(ptr);
#elif defined(CONFIG_RT_OCF_BUDDY_MEM_SYS)
	rt_list_s *buddy_list = mInfo.buddy_list;
	mem_buddy_info_s *mem_block_info = rt_list_search(buddy_list, RT_MEMBER_OFFSET(mem_buddy_info_s, address), RT_MEMBER_SIZE(mem_buddy_info_s, address), &ptr);
	if (resize > mem_block_info->block_size) {
		temp = rt_mem_buddy_alloc(&mInfo, resize);
		RT_VERIFY_NON_NULL_RET(temp, TAG, "Memory is full", NULL);

		size = mem_block_info->alloc_size;

		memcpy(temp, ptr, (size > resize ? resize : size));

		rt_mem_buddy_free(&mInfo, ptr);
	} else {
		mem_block_info->alloc_size = resize;
	}
#endif

	return temp;
}

#ifdef CONFIG_RT_OCF_TRACE_MEMORY
void __rt_mem_free(void *ptr, const char *func)
#else
void __rt_mem_free(void *ptr)
#endif
{
	RT_VERIFY_NON_NULL_VOID(ptr, TAG, NULL);
	unsigned int size = 0;
#if defined(CONFIG_RT_OCF_KERNEL_MEM_SYS)
	size = rt_mem_kernel_free(&mInfo, ptr);
#elif defined(CONFIG_RT_OCF_BUDDY_MEM_SYS)
	size = rt_mem_buddy_free(&mInfo, ptr);
#else
	(void)size;
#endif

#ifdef CONFIG_RT_OCF_TRACE_MEMORY
	rt_mem_append_log(func, size, 0, ptr);
#endif							/* CONFIG_RT_OCF_TRACE_MEMORY */
	return;
}

void rt_mem_cpy(void *dst, const void *src, int size)
{
#ifdef CONFIG_RT_OCF_TRACE_MEMORY
	RT_LOG_D(TAG, "rt_mem_cpy");
#endif							/* CONFIG_RT_OCF_TRACE_MEMORY */

	if (!dst || !src || size == 0) {
		return;
	}

	memcpy(dst, src, size);
}

#ifdef CONFIG_RT_OCF_TRACE_MEMORY
void *__rt_mem_dup(const void *ptr, int size, const char *func)
#else
void *__rt_mem_dup(const void *ptr, int size)
#endif
{
	void *ret = NULL;
#ifdef CONFIG_RT_OCF_TRACE_MEMORY
	RT_LOG_D(TAG, "rt_mem_dup");
	ret = __rt_mem_alloc(size, func);
#else
	ret = __rt_mem_alloc(size);
#endif

	rt_mem_cpy(ret, ptr, size);

	return ret;
}

void rt_mem_pool_terminate(void)
{
	RT_LOG_D(TAG, "%s", __func__);

#if defined(CONFIG_RT_OCF_KERNEL_MEM_SYS)
	int ret;
	if ((ret = rt_mem_kernel_terminate(&mInfo)) != 0) {
		RT_LOG_F(TAG, "#########################################################");
		RT_LOG_F(TAG, "########## Memory Leak Occurs: [%8d bytes] #########", ret);
		RT_LOG_F(TAG, "#########################################################");
	}
#elif defined(CONFIG_RT_OCF_BUDDY_MEM_SYS)
	// TODO: Need to terminate logic for buddy system.
	// rt_mem_buddy_terminate(&mInfo);
#endif

#ifdef CONFIG_RT_OCF_TRACE_MEMORY
	print_mem_log();
	rt_mem_terminate_log();
#endif
}

mem_info_s *getMemInfo(void)
{
	return &mInfo;
}

void print_mem_info(void)
{
	RT_LOG_D(TAG, "==================================================");
#if defined(CONFIG_RT_OCF_KERNEL_MEM_SYS)
	RT_LOG_D(TAG, "Current: %d\tPeak: %d", mInfo.current, mInfo.peak);
#else
	RT_LOG_D(TAG, "Current: %d\tPeak: %d\t\tTotal: %d", mInfo.current, mInfo.peak, mInfo.total);
#endif
	RT_LOG_D(TAG, "==================================================");
}

void print_mem_log(void)
{
#ifdef CONFIG_RT_OCF_TRACE_MEMORY
	int cnt = 0;
	rt_node_s *itr = mInfo.mem_log_list->head;
	printf("===================================================================================\n");
	printf("  %2s   %-17s   %10s   %5s   %5s    %5s    %5s    %8s", "No.", "Func", "Address", "Size", "Req", "Cur", "Peak", "Frag(E)\n");
	printf("-----------------------------------------------------------------------------------\n");
	while (itr) {
		mem_logger_s *var = (mem_logger_s *) rt_list_get_item(mInfo.mem_log_list, itr);
		itr = itr->next;
#if defined(CONFIG_RT_OCF_BUDDY_MEM_SYS)
		printf(" %3d   %-20.18s  %10p   %5d   %5s    %5d    %5d    %.3f\n", ++cnt, var->func, var->address, var->size, (var->type == 0) ? "Free" : "Alloc", var->current, var->peak, var->external_frag_ratio);
#else
		printf(" %3d   %-20.18s  %10p   %5d   %5s    %5d    %5d    %s\n", ++cnt, var->func, var->address, var->size, (var->type == 0) ? "Free" : "Alloc", var->current, var->peak, "None");
#endif
	}
	printf("===================================================================================\n");
#else
	printf("==== Please Enable CONFIG_RT_OCF_TRACE_MEMORY ====\n");
#endif
}

#ifdef CONFIG_RT_OCF_TRACE_MEMORY
static void rt_mem_pool_init_log(void)
{
	static rt_list_s rt_mem_log_list;
	mInfo.mem_log_list = &rt_mem_log_list;
	rt_list_init(mInfo.mem_log_list, sizeof(mem_logger_s), RT_MEMBER_OFFSET(mem_logger_s, node));
}

static void rt_mem_append_log(const char *func, int size, uint8_t type, void *address)
{
	mem_logger_s *mem_log_item = (mem_logger_s *)malloc(sizeof(mem_logger_s));
	mem_log_item->func = (char *)func;
	mem_log_item->size = size;
	mem_log_item->current = mInfo.current;
	mem_log_item->peak = mInfo.peak;
	mem_log_item->type = type;
	mem_log_item->address = address;
#if defined(CONFIG_RT_OCF_BUDDY_MEM_SYS)
	mInfo.external_frag_ratio = rt_mem_buddy_get_external_frag(&mInfo);
	mem_log_item->external_frag_ratio = mInfo.external_frag_ratio;
#endif
	rt_list_insert(mInfo.mem_log_list, &mem_log_item->node);
}

static void rt_mem_terminate_log(void)
{
	rt_node_s *itr = mInfo.mem_log_list->head;
	while (itr) {
		mem_logger_s *var = (mem_logger_s *) rt_list_delete_by_node(mInfo.mem_log_list, itr);
		itr = itr->next;
		free(var);
	}
}
#endif
