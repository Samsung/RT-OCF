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
#include <pthread.h>
#include <errno.h>
#include "rt_event.h"
#include "rt_timer.h"
#include "rt_mem.h"

static int g_value;
TEST_GROUP(test_event);

TEST_SETUP(test_event)
{
	g_value = 0;
	rt_mem_pool_init();
	rt_event_init();
}

TEST_TEAR_DOWN(test_event)
{
	g_value = 0;
	rt_event_terminate();
	rt_mem_pool_terminate();
}

TEST(test_event, rt_event_timedwait_return_ok)
{

	int rc;
	rt_clock_time_t timeout;
	timeout = rt_clock_time() + RT_CLOCK_SECOND * 1;

	rc = rt_event_timedwait(timeout);

	TEST_ASSERT_EQUAL_INT(ETIMEDOUT, rc);

}

/*
// failed in Tizen RT
// :48:TEST(test_event, rt_event_timedwait_ok_dueto_timeout):FAIL: Unity 64-bit Support Disabled

TEST(test_event, rt_event_timedwait_ok_dueto_timeout)
{

	rt_clock_time_t timeout, start, end;

	timeout = rt_clock_time() + RT_CLOCK_SECOND * 2;

	start = rt_clock_time();
	rt_event_timedwait(true, timeout);
	end = rt_clock_time();

	TEST_ASSERT_UINT64_WITHIN((RT_CLOCK_SECOND / 2), timeout, end);
}
*/
static void *change_value(void *data)
{

	usleep(100);
	g_value = *(int *)data;
	rt_event_set_signal();
	return NULL;
}

TEST(test_event, rt_event_timedwait_ok_dueto_event_by_checking_value)
{

	rt_clock_time_t timeout;
	pthread_t thread;
	int a = 3;

	timeout = rt_clock_time() + RT_CLOCK_SECOND * 2;
	g_value = 0;
	pthread_create(&thread, NULL, change_value, (void *)&a);

	rt_event_timedwait(timeout);

	pthread_join(thread, NULL);

	TEST_ASSERT_EQUAL_INT(a, g_value);

}

TEST(test_event, rt_event_timedwait_ok_dueto_event_by_checking_time)
{

	rt_clock_time_t timeout, start, end;
	pthread_t thread;
	int a = 6;

	timeout = rt_clock_time() + (RT_CLOCK_SECOND / 1000000) * 700;
	g_value = 0;
	pthread_create(&thread, NULL, change_value, (void *)&a);

	start = rt_clock_time();
	rt_event_timedwait(timeout);
	end = rt_clock_time();

	pthread_join(thread, NULL);
	TEST_ASSERT_TRUE((end - start) < (RT_CLOCK_SECOND * 2));
}

TEST(test_event, rt_event_wait_ok_dueto_event)
{

	rt_clock_time_t timeout;
	pthread_t thread;
	int a = 9;

	timeout = rt_clock_time() + (RT_CLOCK_SECOND / 1000000) * 700;
	g_value = 0;
	pthread_create(&thread, NULL, change_value, (void *)&a);

	rt_event_wait();

	pthread_join(thread, NULL);
	TEST_ASSERT_EQUAL_INT(a, g_value);
}

TEST_GROUP_RUNNER(test_event)
{
	RUN_TEST_CASE(test_event, rt_event_timedwait_return_ok);
//  RUN_TEST_CASE(test_event, rt_event_timedwait_ok_dueto_timeout);
	RUN_TEST_CASE(test_event, rt_event_timedwait_ok_dueto_event_by_checking_value);
	RUN_TEST_CASE(test_event, rt_event_timedwait_ok_dueto_event_by_checking_time);
	RUN_TEST_CASE(test_event, rt_event_wait_ok_dueto_event);
}

#ifndef CONFIG_ENABLE_RT_OCF

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_event);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
