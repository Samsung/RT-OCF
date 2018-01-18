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

#include <inttypes.h>
#include <unistd.h>
#include "unity.h"
#include "unity_fixture.h"
#include "rt_timer.h"

TEST_GROUP(test_timer);

TEST_SETUP(test_timer)
{
}

TEST_TEAR_DOWN(test_timer)
{
}

TEST(test_timer, timer_expired_test)
{
	// Given
	rt_timer_s beforeTime;
	rt_timer_set(&beforeTime, 0.2 * RT_CLOCK_SECOND);

	// When

	// Then
	TEST_ASSERT_EQUAL_INT(0, rt_timer_expired(&beforeTime));
}

TEST(test_timer, timer_interval_test)
{
	// Given
	uint8_t i = 0;
	rt_timer_s beforeTime, afterTime;
	rt_timer_set(&beforeTime, 0.2 * RT_CLOCK_SECOND);

	// When
	for (i = 0; i < 10; i++) {
		if (rt_timer_expired(&beforeTime)) {
			break;
		}
		usleep(100000);			//100ms
	}
	rt_timer_restart(&afterTime);

	// Then
	TEST_ASSERT_EQUAL_INT(0, (afterTime.start - beforeTime.start - beforeTime.interval) / RT_CLOCK_SECOND);
}

TEST(test_timer, timer_restart_test)
{
	// Given
	rt_timer_s beforeTime;
	rt_timer_set(&beforeTime, 0.2 * RT_CLOCK_SECOND);

	// When
	usleep(100000);				//100ms
	rt_timer_restart(&beforeTime);
	usleep(100000);				//100ms

	// Then
	TEST_ASSERT_EQUAL_INT(0, rt_timer_expired(&beforeTime));
}

TEST_GROUP_RUNNER(test_timer)
{
	RUN_TEST_CASE(test_timer, timer_expired_test);
	RUN_TEST_CASE(test_timer, timer_interval_test);
	RUN_TEST_CASE(test_timer, timer_restart_test);
}

#ifndef CONFIG_IOTIVITY_RT

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_timer);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
