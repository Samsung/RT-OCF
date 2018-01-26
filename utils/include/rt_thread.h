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

#ifndef __RT_OCF_THREAD_H
#define __RT_OCF_THREAD_H

#include <pthread.h>
#include "ocf_types.h"

typedef void *(*rt_thread_handler)(void *);
typedef void (*rt_thread_terminate_handler)(void *);

typedef struct {
	pthread_t thread;
	pthread_attr_t thread_attr;
} rt_thread_s;

/**
 * @param[in]	size	default is set to THREAD_STACK_SIZE(8192).
 */
ocf_result_t rt_thread_init(rt_thread_s *thread_info, rt_thread_handler handler, const char *name, long size, void *user_data);
// dummy terminate_handler makes it call pthread_join() instead of pthread_cancel()
ocf_result_t rt_thread_terminate(rt_thread_s *thread_info, rt_thread_terminate_handler terminate_handler, void *user_data);

#endif							/* __RT_OCF_THREAD_H */
