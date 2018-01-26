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

/*
Needed :
	memset, memcpy, memdup

Module :
	Simple GC
*/

#ifndef __RT_OCF_MEM_H
#define __RT_OCF_MEM_H

#include <stdio.h>
#include <stdint.h>
#include "ocf_types.h"
#include "rt_list.h"

#ifdef CONFIG_RT_OCF_TRACE_MEMORY
typedef struct _mem_logger {
	char *func;
	int size;
	int current;
	int peak;
	uint8_t type;
	void *address;
	float external_frag_ratio;
	rt_node_s node;
} mem_logger_s;

#define rt_mem_alloc(size) (void *)__rt_mem_alloc(size, __FUNCTION__)
#define rt_mem_free(ptr) do {__rt_mem_free(ptr, __FUNCTION__); } while (0)
#define rt_mem_dup(ptr, size) (void *)__rt_mem_dup(ptr, size, __FUNCTION__)
#else
#define rt_mem_alloc(size) (void *)__rt_mem_alloc(size)
#define rt_mem_free(ptr) do {__rt_mem_free(ptr); } while (0)
#define rt_mem_dup(ptr, size) (void *)__rt_mem_dup(ptr, size)
#endif

#ifdef CONFIG_ENABLE_RT_OCF
#define OCF_RT_MEM_POOL_SIZE 1024 * 128
#else
#define OCF_RT_MEM_POOL_SIZE 1024 * 256
#endif

typedef struct _mem_info {
	int peak;
	int current;				// Sum of memory that users requested
	int total;
	void *ptr;
	void *address;
#if defined(CONFIG_RT_OCF_KERNEL_MEM_SYS)
	rt_list_s *kernel_list;
#elif defined(CONFIG_RT_OCF_BUDDY_MEM_SYS)
	int occupied;				// Sum of allocated physical memory
	float external_frag_ratio;
	rt_list_s *buddy_list;
#endif
#ifdef CONFIG_RT_OCF_TRACE_MEMORY
	rt_list_s *mem_log_list;
#endif
} mem_info_s;

typedef struct _mem_assign_info {
	int size;
	void *address;
	rt_node_s node;
} mem_assign_info_s;

typedef struct _mem_remain_info {
	char *func;
	int size;
	void *address;
} mem_remain_info_s;

ocf_result_t rt_mem_pool_init(void);

#ifdef CONFIG_RT_OCF_TRACE_MEMORY
void *__rt_mem_alloc(int size, const char *func);
void __rt_mem_free(void *ptr, const char *func);
void *__rt_mem_dup(const void *ptr, int size, const char *func);
#else
void *__rt_mem_alloc(int size);
void __rt_mem_free(void *ptr);
void *__rt_mem_dup(const void *ptr, int size);
#endif

void *rt_mem_realloc(void *ptr, int resize);

void rt_mem_cpy(void *dst, const void *src, int size);
void rt_mem_pool_terminate(void);
mem_info_s *getMemInfo(void);

void print_mem_info(void);
void print_mem_log(void);
#endif							/* __RT_OCF_MEM_H */
