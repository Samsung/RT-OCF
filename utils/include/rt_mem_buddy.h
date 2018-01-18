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

#ifndef __IOTIVITY_RT_MEM_BUDDY_H
#define __IOTIVITY_RT_MEM_BUDDY_H

#include "rt_list.h"
#include "rt_mem.h"
#include "rt_logger.h"

typedef struct _mem_buddy_info {
	void *address;
	uint32_t alloc_size;
	uint32_t block_size;
	rt_node_s node;
} mem_buddy_info_s;

ocf_result_t rt_mem_buddy_init(mem_info_s *mInfo);
void *rt_mem_buddy_alloc(mem_info_s *mInfo, uint32_t size);
static void *allocate_mem_block(mem_info_s *mInfo, mem_buddy_info_s *var, uint32_t size);
unsigned int rt_mem_buddy_free(mem_info_s *mInfo, void *ptr);
float rt_mem_buddy_get_external_frag(mem_info_s *mInfo);
static uint8_t check_direction(uint32_t pos, uint32_t total, uint32_t block_size);
static void merge_block(mem_info_s *mInfo, mem_buddy_info_s *var);
static void print_buddy_list(mem_info_s *mInfo);

#endif							/* __IOTIVITY_RT_MEM_BUDDY_H */
