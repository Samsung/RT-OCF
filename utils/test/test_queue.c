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
#include "rt_thread.h"
#include "rt_mem.h"
#include "rt_queue.h"

#define MALLOC() (rt_queue_element_s*)rt_mem_alloc(sizeof(rt_queue_element_s))

static rt_queue_s queue;

TEST_GROUP(test_queue);

TEST_SETUP(test_queue)
{
	rt_mem_pool_init();
	rt_queue_init(&queue);
}

TEST_TEAR_DOWN(test_queue)
{
	rt_queue_terminate(&queue, NULL);
	rt_mem_pool_terminate();
}

TEST(test_queue, queue_init_test)
{
	TEST_ASSERT_NULL(queue.front);
	TEST_ASSERT_NULL(queue.rear);
	TEST_ASSERT_EQUAL_INT(0, queue.count);
}

TEST(test_queue, queue_push_test)
{
	char *str1 = "ABC";
	char *str2 = "DEF";

	rt_queue_element_s *element1 = MALLOC();
	element1->data = rt_mem_dup(str1, strlen(str1) + 1);
	rt_queue_element_s *element2 = MALLOC();
	element2->data = rt_mem_dup(str2, strlen(str2) + 1);

	rt_queue_push(&queue, element1);
	rt_queue_push(&queue, element2);

	TEST_ASSERT_EQUAL_INT(2, queue.count);
}

TEST(test_queue, queue_push_without_init_queue_test)
{
	char *str1 = "ABC";

	rt_queue_element_s *element1 = MALLOC();
	element1->data = rt_mem_dup(str1, strlen(str1) + 1);

	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, rt_queue_push(NULL, element1));

	rt_queue_remove_item(element1, NULL);
}

TEST(test_queue, queue_pop_test)
{
	char *str1 = "ABCDEFGHIJKLM";
	char *str2 = "NOPQRSTUVWXYZ";

	rt_queue_element_s *element1 = MALLOC();
	element1->data = rt_mem_dup(str1, strlen(str1) + 1);
	rt_queue_element_s *element2 = MALLOC();
	element2->data = rt_mem_dup(str2, strlen(str2) + 1);

	rt_queue_push(&queue, element1);
	rt_queue_push(&queue, element2);

	TEST_ASSERT_EQUAL_INT(2, queue.count);

	rt_queue_element_s *element3 = rt_queue_pop(&queue);
	TEST_ASSERT_EQUAL_PTR(element1, element3);
	TEST_ASSERT_EQUAL_STRING(str1, (char *)element3->data);
	TEST_ASSERT_EQUAL_INT(1, queue.count);
	rt_queue_remove_item(element3, NULL);

	rt_queue_element_s *element4 = rt_queue_pop(&queue);
	TEST_ASSERT_EQUAL_PTR(element2, element4);
	TEST_ASSERT_EQUAL_STRING(str2, (char *)element4->data);
	TEST_ASSERT_EQUAL_INT(0, queue.count);
	rt_queue_remove_item(element4, NULL);

	TEST_ASSERT_NULL(queue.front);
	TEST_ASSERT_NULL(queue.rear);
}

#define NUM_THD 5

#ifdef CONFIG_ENABLE_RT_OCF
static int num_node = 50;
#else
static int num_node = 1500;
#endif

static void *push_item(void *data)
{
	int i;

	for (i = 0; i < num_node; i++) {
		rt_queue_element_s *element1 = MALLOC();
		rt_queue_push(&queue, element1);
	}
	return 0;
}

static void dummy_func(void *data)
{
	// do nothing. it makes rt_thread_terminate() call pthread_join
	return;
}

TEST(test_queue, queue_check_totalnum_after_push_numerous_items_on_threads)
{
	rt_thread_s thread_info[NUM_THD];

	// When 각각의 Thread에서 n개씩 동시에 push를 했을 때
	int i;
	for (i = 0; i < NUM_THD; ++i) {
		rt_thread_init(&(thread_info[i]), push_item, NULL, 0, NULL);
	}

	for (i = 0; i < NUM_THD; ++i) {
		rt_thread_terminate(&(thread_info[i]), dummy_func, NULL);
	}

	// Then count가 push 한만큼 늘어나 있고, pop을 했을 때 정상적으로 동작한다.
	TEST_ASSERT_EQUAL_INT(num_node * NUM_THD, queue.count);
	int n = 0;
	while (queue.front != NULL || queue.rear != NULL) {
		rt_queue_element_s *element = rt_queue_pop(&queue);
		rt_queue_remove_item(element, NULL);
		n++;

	}
	TEST_ASSERT_EQUAL_INT(num_node * NUM_THD, n);
	TEST_ASSERT_EQUAL_INT(0, queue.count);
}

TEST(test_queue, queue_pop_without_init_queue_test)
{
	TEST_ASSERT_EQUAL_PTR(NULL, rt_queue_pop(NULL));
}

TEST(test_queue, queue_remove_un_alloced_item_test)
{
	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, rt_queue_remove_item(NULL, NULL));
}

TEST(test_queue, queue_terminate_without_init_queue_test)
{
	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, rt_queue_terminate(NULL, NULL));
}

TEST_GROUP_RUNNER(test_queue)
{
	RUN_TEST_CASE(test_queue, queue_init_test);
	RUN_TEST_CASE(test_queue, queue_push_test);
	RUN_TEST_CASE(test_queue, queue_push_without_init_queue_test);
	RUN_TEST_CASE(test_queue, queue_check_totalnum_after_push_numerous_items_on_threads);
	RUN_TEST_CASE(test_queue, queue_pop_test);
	RUN_TEST_CASE(test_queue, queue_pop_without_init_queue_test);
	RUN_TEST_CASE(test_queue, queue_remove_un_alloced_item_test);
	RUN_TEST_CASE(test_queue, queue_terminate_without_init_queue_test);
}

#ifndef CONFIG_ENABLE_RT_OCF

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_queue);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
