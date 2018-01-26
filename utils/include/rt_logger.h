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

#ifndef __RT_OCF_LOGGER_H
#define __RT_OCF_LOGGER_H

#include <stdint.h>

typedef enum {
	OCF_LOG_DEBUG = 0,
	OCF_LOG_INFO,
	OCF_LOG_WARNING,
	OCF_LOG_ERROR,
	OCF_LOG_FATAL,
} ocf_log_level_t;

#ifdef CONFIG_RT_OCF_LOG_DEBUG
#define LOGLEVEL_DEBUG 1
#else
#define LOGLEVEL_DEBUG 0
#endif

#ifdef CONFIG_RT_OCF_LOG_INFO
#define LOGLEVEL_INFO (1 << 1)
#else
#define LOGLEVEL_INFO 0
#endif

#ifdef CONFIG_RT_OCF_LOG_WARNING
#define LOGLEVEL_WARNING (1 << 2)
#else
#define LOGLEVEL_WARNING 0
#endif

#ifdef CONFIG_RT_OCF_LOG_ERROR
#define LOGLEVEL_ERROR (1 << 3)
#else
#define LOGLEVEL_ERROR 0
#endif

#ifdef CONFIG_RT_OCF_LOG_FATAL
#define LOGLEVEL_FATAL (1 << 4)
#else
#define LOGLEVEL_FATAL 0
#endif

#ifdef CONFIG_RT_OCF_DEBUG
#define LOGLEVEL (LOGLEVEL_DEBUG | LOGLEVEL_INFO | LOGLEVEL_WARNING | LOGLEVEL_ERROR | LOGLEVEL_FATAL)
#else
#define LOGLEVEL 0
#endif

// TODO :  refactoring is needed - __rt_log*() are always called unnecessarily.
#define RT_LOG(LEVEL, TAG, fmt, ...) __rt_log(LEVEL, TAG, fmt, ##__VA_ARGS__)
#define RT_LOG_BUFFER(LEVEL, TAG, buffer, buffer_size) __rt_log_buffer(LEVEL, TAG, buffer, buffer_size)

#define RT_LOG_D(TAG, fmt, ...) RT_LOG(OCF_LOG_DEBUG, TAG, fmt, ##__VA_ARGS__)
#define RT_LOG_I(TAG, fmt, ...) RT_LOG(OCF_LOG_INFO, TAG, fmt, ##__VA_ARGS__)
#define RT_LOG_W(TAG, fmt, ...) RT_LOG(OCF_LOG_WARNING, TAG, fmt, ##__VA_ARGS__)
#define RT_LOG_E(TAG, fmt, ...) RT_LOG(OCF_LOG_ERROR, TAG, fmt, ##__VA_ARGS__)
#define RT_LOG_F(TAG, fmt, ...) RT_LOG(OCF_LOG_FATAL, TAG, fmt, ##__VA_ARGS__)

#define RT_LOG_BUFFER_D(TAG, buffer, buffer_size) RT_LOG_BUFFER(OCF_LOG_DEBUG, TAG, buffer, buffer_size)
#define RT_LOG_BUFFER_I(TAG, buffer, buffer_size) RT_LOG_BUFFER(OCF_LOG_INFO, TAG, buffer, buffer_size)
#define RT_LOG_BUFFER_W(TAG, buffer, buffer_size) RT_LOG_BUFFER(OCF_LOG_WARNING, TAG, buffer, buffer_size)
#define RT_LOG_BUFFER_E(TAG, buffer, buffer_size) RT_LOG_BUFFER(OCF_LOG_ERROR, TAG, buffer, buffer_size)
#define RT_LOG_BUFFER_F(TAG, buffer, buffer_size) RT_LOG_BUFFER(OCF_LOG_FATAL, TAG, buffer, buffer_size)

void __rt_log(ocf_log_level_t level, const char *tag, const char *fmt, ...);
void __rt_log_buffer(ocf_log_level_t level, const char *tag, const void *buffer, int32_t buffer_size);

#endif							/* __RT_OCF_LOGGER_H */
