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

#ifndef __IOTIVITY_RT_MEM_KERNEL_H
#define __IOTIVITY_RT_MEM_KERNEL_H

#include "rt_mem.h"

ocf_result_t rt_mem_kernel_init(mem_info_s *mInfo);
void *rt_mem_kernel_alloc(mem_info_s *mInfo, uint32_t size);
unsigned int rt_mem_kernel_free(mem_info_s *mInfo, void *ptr);
int rt_mem_kernel_terminate(mem_info_s *mInfo);
#endif							/* __IOTIVITY_RT_MEM_KERNEL_H */
