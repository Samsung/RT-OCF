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
#include "rt_thread.h"

static uint8_t terminate_flag = 0;

void *dummy_function(void *data)
{
	__sync_bool_compare_and_swap(&terminate_flag, 0, 1);

	while (terminate_flag != 2) {
		usleep(10 * 1000);
	}

	return NULL;
}

void dummy_function_terminate(void *user_data)
{
	while (terminate_flag != 1) {
		usleep(10 * 1000);
	}

	__sync_bool_compare_and_swap(&terminate_flag, 1, 2);
}

TEST_GROUP(test_thread);

TEST_SETUP(test_thread)
{
	terminate_flag = 0;
}

TEST_TEAR_DOWN(test_thread)
{
}

TEST(test_thread, thread_init_test_return_ok)
{
	rt_thread_s thread_info;

	TEST_ASSERT_EQUAL_INT(OCF_OK, rt_thread_init(&(thread_info), dummy_function, "test_OK", 0, NULL));

	rt_thread_terminate(&(thread_info), dummy_function_terminate, NULL);
}

TEST(test_thread, thread_init_test_return_fail_by_invalid_info_param)
{
	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, rt_thread_init(NULL, dummy_function, "test_thread_info_Fail", 0, NULL));
}

TEST(test_thread, thread_init_test_return_fail_by_invalid_func_param)
{
	rt_thread_s thread_info;

	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, rt_thread_init(&(thread_info), NULL, "test_thread_info_Fail", 0, NULL));
}

TEST(test_thread, thread_terminate_test_return_fail_by_invalid_info_param)
{
	rt_thread_s thread_info;

	rt_thread_init(&(thread_info), dummy_function, "w_handler", 0, NULL);

	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, rt_thread_terminate(NULL, dummy_function_terminate, NULL));
	rt_thread_terminate(&(thread_info), dummy_function_terminate, NULL);
}

TEST(test_thread, thread_terminate_test_return_ok_with_terminate_handler)
{
	rt_thread_s thread_info;

	rt_thread_init(&(thread_info), dummy_function, "w_handler", 0, NULL);

	TEST_ASSERT_EQUAL_INT(OCF_OK, rt_thread_terminate(&(thread_info), dummy_function_terminate, NULL));
}

TEST(test_thread, thread_terminate_test_return_ok_without_terminate_handler)
{
	rt_thread_s thread_info;

	rt_thread_init(&(thread_info), dummy_function, "wo_handler", 0, NULL);

	TEST_ASSERT_EQUAL_INT(OCF_OK, rt_thread_terminate(&(thread_info), NULL, NULL));
}

// can we check the status of terminate thread whether it is able to run out of while

TEST_GROUP_RUNNER(test_thread)
{
	RUN_TEST_CASE(test_thread, thread_init_test_return_ok);
	RUN_TEST_CASE(test_thread, thread_init_test_return_fail_by_invalid_info_param);
	RUN_TEST_CASE(test_thread, thread_init_test_return_fail_by_invalid_func_param);
	RUN_TEST_CASE(test_thread, thread_terminate_test_return_fail_by_invalid_info_param);
	RUN_TEST_CASE(test_thread, thread_terminate_test_return_ok_with_terminate_handler);
	RUN_TEST_CASE(test_thread, thread_terminate_test_return_ok_without_terminate_handler);
}

#ifndef CONFIG_IOTIVITY_RT

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_thread);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
