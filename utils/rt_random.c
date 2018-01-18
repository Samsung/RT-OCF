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

#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include "rt_random.h"
#include "rt_timer.h"

void rt_random_init(void)
{
	srand(rt_clock_time());
}

uint16_t rt_random_rand(void)
{
	return rand();
}

void rt_random_rand_to_buffer(uint8_t *buffer, size_t size)
{
	int i;
	uint16_t var;
	size_t remain = size;
	for (i = 0; i < size; i += 2, remain -= 2) {
		var = rt_random_rand();
		memcpy(buffer + i, &var, (remain < 2) ? 1 : 2);
	}
}
