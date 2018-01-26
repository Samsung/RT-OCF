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
#include <string.h>
#include "rt_mem.h"
#include "rt_message_queue.h"
#include "ocf_types.h"
#include "rt_logger.h"
#include "test_common.h"

#include <time.h>
#include <sys/time.h>

#define TAG "TEST_QUEUETHREAD"

#define MAX_ENQUEUE_COUNT 100

static rt_message_queue_s queue;
static pthread_cond_t g_condition;
static pthread_mutex_t g_mutex;
static char *str = "queuethread test!";

typedef struct {
	char *str;
	int i;
} str_s;

TEST_GROUP(test_message_queue);

TEST_SETUP(test_message_queue)
{
	rt_mem_pool_init();

	pthread_mutex_init(&g_mutex, NULL);
	pthread_cond_init(&g_condition, NULL);
}

TEST_TEAR_DOWN(test_message_queue)
{
	rt_message_queue_terminate(&queue);
	pthread_cond_destroy(&g_condition);
	pthread_mutex_destroy(&g_mutex);
	rt_mem_pool_terminate();
}

static void test_func(void *data)
{
	str_s *m_str = (str_s *) data;

	static int i = 0;
	TEST_ASSERT_EQUAL_STRING(str, m_str->str);

	if (++i == MAX_ENQUEUE_COUNT) {
		usleep(10 * 1000);
		pthread_mutex_lock(&g_mutex);
		pthread_cond_signal(&g_condition);
		pthread_mutex_unlock(&g_mutex);
	}
}

TEST(test_message_queue, init)
{
	// When
	ocf_result_t ret = rt_message_queue_init(&queue, test_func, NULL, "message_queue");

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
}

TEST(test_message_queue, init_invalid_param)
{
	// When
	ocf_result_t ret = rt_message_queue_init(NULL, test_func, NULL, "message_queue");

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, ret);
}

static void my_str_free_func(void *data)
{
	str_s *my_str = (str_s *) data;
	rt_mem_free(my_str->str);
}

TEST(test_message_queue, enqueue)
{
	// Given
	rt_message_queue_init(&queue, test_func, my_str_free_func, "message_queue");

	// When
	int i;
	ocf_result_t ret = 0;
	for (i = 0; i < MAX_ENQUEUE_COUNT; i++) {
		usleep(1 * 1000);
		str_s *my_str = (str_s *) rt_mem_alloc(sizeof(str_s));
		my_str->str = rt_mem_dup(str, strlen(str) + 1);
		ret = rt_message_queue_enqueue(&queue, my_str);
	}
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);

	int result = wait_for_condition(&g_mutex, &g_condition);
	TEST_ASSERT_EQUAL(0, result);
}

static void enqueue_instanly_after_init_callback(void *data)
{
	pthread_mutex_lock(&g_mutex);
	pthread_cond_signal(&g_condition);
	pthread_mutex_unlock(&g_mutex);
}

TEST(test_message_queue, enqueue_instanly_after_init)
{
	// Given
	rt_message_queue_init(&queue, enqueue_instanly_after_init_callback, NULL, "message_queue");

	// When
	char ch = 'a';
	rt_message_queue_enqueue(&queue, rt_mem_dup(&ch, sizeof(char)));

	// Then
	int result = wait_for_condition(&g_mutex, &g_condition);
	TEST_ASSERT_EQUAL(0, result);
}

TEST(test_message_queue, enqueue_invalid_param)
{
	// Given
	rt_message_queue_init(&queue, test_func, NULL, "message_queue");

	char *var = rt_mem_dup(str, strlen(str) + 1);
	ocf_result_t ret = rt_message_queue_enqueue(NULL, var);

	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, ret);
	rt_mem_free(var);

	ret = rt_message_queue_enqueue(&queue, NULL);

	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, ret);
}

TEST(test_message_queue, terminate)
{
	rt_message_queue_init(&queue, test_func, NULL, "message_queue");
	rt_message_queue_terminate(&queue);
	mem_info_s *mem = getMemInfo();
	TEST_ASSERT_EQUAL_INT(0, mem->current);
}

TEST_GROUP_RUNNER(test_message_queue)
{
	RUN_TEST_CASE(test_message_queue, init);
	RUN_TEST_CASE(test_message_queue, init_invalid_param);
	RUN_TEST_CASE(test_message_queue, enqueue);
	RUN_TEST_CASE(test_message_queue, enqueue_instanly_after_init);
	RUN_TEST_CASE(test_message_queue, enqueue_invalid_param);
	RUN_TEST_CASE(test_message_queue, terminate);
}

#ifndef CONFIG_ENABLE_RT_OCF

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_message_queue);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
