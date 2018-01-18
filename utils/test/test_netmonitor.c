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
#include "rt_netmonitor.h"
#include "rt_mem.h"
#include "rt_logger.h"
#include "Mocksocket.h"
#include "ocf_types.h"

#define NETLINK_STATUS 1136
#define TEST_NETMONITOR  "tdd_net_mon"

TEST_GROUP(test_netmonitor);

TEST_SETUP(test_netmonitor)
{
	rt_mem_pool_init();
	rt_init_netmonitor();

	quit_netlink_thread();
}

TEST_TEAR_DOWN(test_netmonitor)
{
	rt_terminate_netmonitor();
	rt_mem_pool_terminate();
}

ssize_t recvmsg_callback_ifup(int __fd, struct msghdr *__message, int __flags, int cmock_num_calls)
{
	return NETLINK_STATUS;
}

ssize_t recvmsg_callback_ifdown(int __fd, struct msghdr *__message, int __flags, int cmock_num_calls)
{
	return NETLINK_STATUS;
}

void wait_for_mutex_free(pthread_mutex_t *mutex)
{
	int i;
	for (i = 0; i != 5; i++) {
		if (pthread_mutex_trylock(mutex) == 0) {
			pthread_mutex_unlock(mutex);
			break;
		}
		usleep(100000);
	}
}

ocf_result_t dummy_function1(ocf_network_status_t status)
{
	return OCF_OK;
}

ocf_result_t dummy_function2(ocf_network_status_t status)
{
	return OCF_OK;
}

TEST(test_netmonitor, rt_register_netmonitor)
{
	TEST_ASSERT_EQUAL_INT(OCF_OK, rt_register_netmonitor(dummy_function1));
	TEST_ASSERT_EQUAL_INT(OCF_OK, rt_register_netmonitor(dummy_function2));
}

TEST(test_netmonitor, rt_register_netmonitor_duplicate_func)
{
	TEST_ASSERT_EQUAL_INT(OCF_OK, rt_register_netmonitor(dummy_function1));
	TEST_ASSERT_EQUAL_INT(OCF_OK, rt_register_netmonitor(dummy_function1));
}

TEST(test_netmonitor, rt_unregister_netmonitor)
{
	// Given
	rt_register_netmonitor(dummy_function1);
	rt_register_netmonitor(dummy_function2);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, rt_unregister_netmonitor(dummy_function1));
}

TEST(test_netmonitor, rt_unregister_netmonitor_unregistered_func)
{
	// Given
	rt_register_netmonitor(dummy_function1);

	// When

	TEST_ASSERT_EQUAL_INT(OCF_ERROR, rt_unregister_netmonitor(dummy_function2));
}

pthread_mutex_t one_callback_mutex;
bool one_callback_called;

ocf_result_t call_one_callback(ocf_network_status_t status)
{
	one_callback_called = true;
	pthread_mutex_unlock(&one_callback_mutex);
	return OCF_OK;
}

TEST_GROUP_RUNNER(test_netmonitor)
{
	RUN_TEST_CASE(test_netmonitor, rt_register_netmonitor);
	RUN_TEST_CASE(test_netmonitor, rt_register_netmonitor_duplicate_func);
	RUN_TEST_CASE(test_netmonitor, rt_unregister_netmonitor);
	RUN_TEST_CASE(test_netmonitor, rt_unregister_netmonitor_unregistered_func);
}

#ifndef CONFIG_IOTIVITY_RT

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_netmonitor);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
