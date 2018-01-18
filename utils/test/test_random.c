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

#include "unity.h"
#include "unity_fixture.h"
#include "rt_random.h"
#include "rt_logger.h"
#include "stdbool.h"

TEST_GROUP(test_random);

TEST_SETUP(test_random)
{
	rt_random_init();
}

TEST_TEAR_DOWN(test_random)
{
}

TEST(test_random, random_rand_test)
{
	// Given
	uint8_t count = 100;
	uint16_t var1;
	uint16_t var2;
	uint16_t var3;

	// When
	do {
		var1 = rt_random_rand();
		var2 = rt_random_rand();
		var3 = rt_random_rand();
		TEST_ASSERT_FALSE(var1 == var2 && var2 == var3);
	} while (count-- > 0);
}

static bool check_equal_array(uint8_t *var1, uint8_t *var2, size_t len)
{
	int i;
	for (i = 0; i < len; i++) {
		if (var1[i] != var2[i]) {
			return false;
		}
	}
	return true;
}

TEST(test_random, random_rand_test_to_buffer_even_size)
{
	// Given
	uint8_t count = 100;
	uint8_t var1[4];
	uint8_t var2[4];

	// When
	do {
		rt_random_rand_to_buffer(var1, sizeof(var1));
		rt_random_rand_to_buffer(var2, sizeof(var2));

		// RT_LOG_BUFFER_D ("TC_RANDOM1", var1, sizeof(var1));
		// RT_LOG_BUFFER_D ("TC_RANDOM2", var2, sizeof(var2));

		TEST_ASSERT_FALSE(check_equal_array(var1, var2, sizeof(var1)));
	} while (count-- > 0);
}

TEST(test_random, random_rand_test_to_buffer_odd_size)
{
	// Given
	uint8_t count = 100;
	uint8_t var1[7];
	uint8_t var2[7];

	// When
	do {
		rt_random_rand_to_buffer(var1, sizeof(var1));
		rt_random_rand_to_buffer(var2, sizeof(var2));

		// RT_LOG_BUFFER_D ("TC_RANDOM1", var1, sizeof(var1));
		// RT_LOG_BUFFER_D ("TC_RANDOM2", var2, sizeof(var2));

		TEST_ASSERT_FALSE(check_equal_array(var1, var2, sizeof(var1)));
	} while (count-- > 0);
}

TEST_GROUP_RUNNER(test_random)
{
	RUN_TEST_CASE(test_random, random_rand_test);
	RUN_TEST_CASE(test_random, random_rand_test_to_buffer_even_size);
	RUN_TEST_CASE(test_random, random_rand_test_to_buffer_odd_size);
}

#ifndef CONFIG_IOTIVITY_RT

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_random);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
