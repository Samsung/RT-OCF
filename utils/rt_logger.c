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
#include <stdarg.h>
#include <string.h>
#include "rt_logger.h"
#include "rt_mem.h"

#define FILTER_TOKEN "/"

const char *RT_LOG_STRING[5] = {
	"DEBUG",
	"INFO",
	"WARNING",
	"ERROR",
	"FATAL"
};

#ifdef CONFIG_IOTIVITY_RT_LOG_FILTER
static bool filter_checker(const char *tag)
{
	char *filter_ptr;
	char filter_str[] = CONFIG_IOTIVITY_RT_LOG_FILTER_TAG;
	filter_ptr = strtok(filter_str, FILTER_TOKEN);

	while (filter_ptr != NULL) {
		if (strcmp(filter_ptr, tag) == 0) {
			return true;
		}
		filter_ptr = strtok(NULL, FILTER_TOKEN);
	}

	return false;
}
#endif

void __rt_log(ocf_log_level_t level, const char *tag, const char *fmt, ...)
{
	if (!(LOGLEVEL & (1 << level))) {
		return;
	}
#ifdef CONFIG_IOTIVITY_RT_LOG_FILTER
	if (!filter_checker(tag)) {
		return;
	}
#endif

	va_list arg;

	printf("[%7s][%s]", RT_LOG_STRING[level], tag);
	va_start(arg, fmt);
	vprintf(fmt, arg);
	va_end(arg);

	printf("\n");
	return;
}

void __rt_log_buffer(ocf_log_level_t level, const char *tag, const void *buffer, int32_t buffer_size)
{
	if (!(LOGLEVEL & (1 << level))) {
		return;
	}
#ifdef CONFIG_IOTIVITY_RT_LOG_FILTER
	if (!filter_checker(tag)) {
		return;
	}
#endif

	uint16_t i = 0;
	const uint8_t *tmp_buffer = buffer;

	if (!tmp_buffer) {
		RT_LOG(level, tag, "buf is NULL");
		return;
	}
	if ((buffer_size <= 0) || (buffer_size >= OCF_RT_MEM_POOL_SIZE)) {
		RT_LOG(level, tag, "buffer_size is out of bound %d", buffer_size);
		return;
	}

	uint8_t print_buffer_len = 0, len = 0;

	printf("[%7s][%s]", RT_LOG_STRING[level], tag);
	while (buffer_size-- > 0) {
		if ((uint16_t)(i & 0xf) == 0) {
			printf(" : ");
			for (len = 0; len < print_buffer_len; ++len) {
				printf("%c", (uint8_t) tmp_buffer[i - len]);
			}
			print_buffer_len = 0;
			printf("\n [%04x] : ", i);
		}
		printf("%02X ", ((uint8_t) tmp_buffer[i]) & 0xff);
		i++;
		print_buffer_len++;
	}

	while ((uint16_t)(i & 0xf)) {
		printf("   ");
		i++;
	}
	if (print_buffer_len) {
		printf(" : ");
		for (len = 0; len < print_buffer_len; ++len) {
			printf("%c", (uint8_t) tmp_buffer[i - 0x10 + len]);
		}
	}
	printf("\n");
}
