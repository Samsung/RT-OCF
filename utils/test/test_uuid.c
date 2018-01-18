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
#include <stdio.h>
#include <time.h>
#include "rt_mem.h"
#include "rt_uuid.h"

TEST_GROUP(test_uuid);

TEST_SETUP(test_uuid)
{
	rt_mem_pool_init();
	rt_random_init();
}

TEST_TEAR_DOWN(test_uuid)
{
	rt_mem_pool_terminate();
}

bool is_same_uuid(rt_uuid_t expected, rt_uuid_t actual)
{
	int i;
	for (i = 0; i != 16; i++) {
		if (expected[i] != actual[i]) {
			return false;
		}
	}
	return true;
}

TEST(test_uuid, str_to_binary)
{
	// Given
	const char *uuid_str = "6f0aac04-2bb0-468d-b57c-16570a26ae48";

	// When
	rt_uuid_t uuid;
	rt_uuid_str2uuid(uuid_str, uuid);
	char actual[RT_UUID_STR_LEN];
	rt_uuid_uuid2str(uuid, actual, RT_UUID_STR_LEN);

	// Then
	TEST_ASSERT_EQUAL_STRING(uuid_str, actual);
}

TEST(test_uuid, is_astrict)
{
	// Given
	rt_uuid_t uuid = { 0x2a, 0, };

	// When

	// Then
	TEST_ASSERT_TRUE(rt_uuid_is_astrict(uuid));
}

TEST_GROUP_RUNNER(test_uuid)
{
	RUN_TEST_CASE(test_uuid, str_to_binary);
	RUN_TEST_CASE(test_uuid, is_astrict);
}

#ifndef CONFIG_IOTIVITY_RT
static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_uuid);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}
#endif
