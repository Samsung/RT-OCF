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

#ifdef CONFIG_IOTIVITY_RT_BUDDY_MEM_SYS
#include "unity.h"
#include "unity_fixture.h"
#include <stdio.h>
#include "rt_mem.h"
#include "rt_list.h"
#include "rt_logger.h"

#define TESTBUDDYMEM	"test_buddy_mem"

static mem_info_s *mem;

TEST_GROUP(test_mem_buddy);

TEST_SETUP(test_mem_buddy)
{
	mem = getMemInfo();
	rt_mem_pool_init();
}

TEST_TEAR_DOWN(test_mem_buddy)
{
	print_mem_log();
	rt_mem_pool_terminate();
}

TEST(test_mem_buddy, default_buddy)
{
	RT_LOG_D(TESTBUDDYMEM, "%p", mem->address);
	RT_LOG_D(TESTBUDDYMEM, "%p", mem->ptr);
	TEST_ASSERT_EQUAL_INT(mem->address, mem->ptr);
}

TEST(test_mem_buddy, getMemInfo_detect_leak)
{
	(int *)rt_mem_alloc(sizeof(int));

	//Then
	TEST_ASSERT_EQUAL_INT(4, rt_mem_buddy_terminate(mem));
}

TEST(test_mem_buddy, alloc_pool_size)
{
	//Given
	int *A = (int *)rt_mem_alloc(OCF_RT_MEM_POOL_SIZE);

	rt_mem_free(A);

	//Then
	TEST_ASSERT_EQUAL_INT(OCF_RT_MEM_POOL_SIZE, mem->peak);
	TEST_ASSERT_EQUAL_INT(0, mem->current);
	TEST_ASSERT_EQUAL_INT(0, mem->occupied);
	TEST_ASSERT_EQUAL_INT(OCF_RT_MEM_POOL_SIZE, mem->total);
}

TEST(test_mem_buddy, alloc4_free2)
{
	//Given
	int *A = (int *)rt_mem_alloc(20);
	int *B = (int *)rt_mem_alloc(35);
	int *C = (int *)rt_mem_alloc(10);
	int *D = (int *)rt_mem_alloc(5);

	rt_mem_free(D);
	rt_mem_free(C);

	A = NULL;
	B = NULL;

	//Then
	TEST_ASSERT_EQUAL_INT(70, mem->peak);
	TEST_ASSERT_EQUAL_INT(55, mem->current);
	TEST_ASSERT_EQUAL_INT(96, mem->occupied);
	TEST_ASSERT_EQUAL_INT(OCF_RT_MEM_POOL_SIZE, mem->total);
}

TEST(test_mem_buddy, alloc_random)
{
	//Given
	int N = 100;
	unsigned int *ptr_list[N];
	int i = 0, count = 0;
	srand(time(NULL));
	for (i = 0; i < N; i++) {
		int size = rand() % 1500;
		unsigned int *ptr = (unsigned int *)rt_mem_alloc(size);
		if (ptr != NULL) {
			ptr_list[count] = ptr;
			count++;
			RT_LOG_D(TESTBUDDYMEM, "%d | size=%d, ptr=%x\n", count, size, ptr);
		}
	}

	for (i = 0; i < count; i++) {
		RT_LOG_D(TESTBUDDYMEM, "%d / %d", i, count);
		rt_mem_free(ptr_list[i]);
	}

	//Then333
	TEST_ASSERT_EQUAL_INT(OCF_RT_MEM_POOL_SIZE, mem->total);
}

TEST(test_mem_buddy, external_frag_ratio_default)
{
	//Given
	TEST_ASSERT_EQUAL_FLOAT(0, mem->external_frag_ratio);
}

TEST(test_mem_buddy, external_frag_ratio_4096_byte)
{
	//Given

	// When
	unsigned int *ptr = (unsigned int *)rt_mem_alloc(4096);

	// Then
	float expected = 1.0f - ((float)(OCF_RT_MEM_POOL_SIZE / 2.0f) / (float)(OCF_RT_MEM_POOL_SIZE - 4096.0f));
	TEST_ASSERT_FLOAT_WITHIN(0.001f, expected, mem->external_frag_ratio);
	rt_mem_free(ptr);
}

TEST(test_mem_buddy, external_frag_ratio_half_byte)
{
	//Given

	// When
	unsigned int *ptr = (unsigned int *)rt_mem_alloc(OCF_RT_MEM_POOL_SIZE >> 1);

	// Then
	TEST_ASSERT_FLOAT_WITHIN(0.001f, 0.0f, mem->external_frag_ratio);
	rt_mem_free(ptr);
}

TEST(test_mem_buddy, external_frag_ratio_half_of_half_byte)
{
	//Given

	// When
	unsigned int *ptr = (unsigned int *)rt_mem_alloc(OCF_RT_MEM_POOL_SIZE >> 2);

	// Then
	float expected = 1 / 3.0f;
	TEST_ASSERT_FLOAT_WITHIN(0.001f, expected, mem->external_frag_ratio);
	rt_mem_free(ptr);
}

TEST(test_mem_buddy, external_frag_ratio_one_of_four_three_of_eight)
{
	//Given

	// When
	unsigned int *ptr1 = (unsigned int *)rt_mem_alloc(OCF_RT_MEM_POOL_SIZE >> 2);
	unsigned int *ptr2 = (unsigned int *)rt_mem_alloc((OCF_RT_MEM_POOL_SIZE >> 3) * 3);

	// Then
	float expected = 1 / 3.0f;
	TEST_ASSERT_FLOAT_WITHIN(0.001f, expected, mem->external_frag_ratio);
	rt_mem_free(ptr1);
	rt_mem_free(ptr2);
}

TEST(test_mem_buddy, alloc_fail_too_large_memory)
{
	// When
	unsigned int *ptr = (unsigned int *)rt_mem_alloc(OCF_RT_MEM_POOL_SIZE + 1);
	TEST_ASSERT_NULL(ptr);

	rt_mem_free(ptr);
}

TEST(test_mem_buddy, alloc_success_max_memory)
{
	// When
	unsigned int *ptr = (unsigned int *)rt_mem_alloc(OCF_RT_MEM_POOL_SIZE);
	TEST_ASSERT_NOT_NULL(ptr);

	rt_mem_free(ptr);
}

TEST(test_mem_buddy, external_frag_ratio_random)
{
	//Given
	int N = 100;
	unsigned int *ptr_list[N];
	int i = 0, count = 0;
	srand(time(NULL));
	for (i = 0; i < N; i++) {
		int size = (rand() % 200) * 16;
		unsigned int *ptr = (unsigned int *)rt_mem_alloc(size);
		if (ptr != NULL) {
			ptr_list[count] = ptr;
			count++;
			RT_LOG_D(TESTBUDDYMEM, "%d | size=%d, ptr=%x\n", count, size, ptr);
		}
	}

	for (i = 0; i < count; i++) {
		RT_LOG_D(TESTBUDDYMEM, "%d / %d", i, count);
		rt_mem_free(ptr_list[i]);
	}
}

TEST_GROUP_RUNNER(test_mem_buddy)
{
	RUN_TEST_CASE(test_mem_buddy, default_buddy);
	RUN_TEST_CASE(test_mem_buddy, getMemInfo_detect_leak);
	RUN_TEST_CASE(test_mem_buddy, alloc_pool_size);
	RUN_TEST_CASE(test_mem_buddy, alloc4_free2);
	RUN_TEST_CASE(test_mem_buddy, alloc_random);
	RUN_TEST_CASE(test_mem_buddy, alloc_fail_too_large_memory);
	RUN_TEST_CASE(test_mem_buddy, alloc_success_max_memory);
	RUN_TEST_CASE(test_mem_buddy, external_frag_ratio_default);
	RUN_TEST_CASE(test_mem_buddy, external_frag_ratio_4096_byte);
	RUN_TEST_CASE(test_mem_buddy, external_frag_ratio_half_byte);
	RUN_TEST_CASE(test_mem_buddy, external_frag_ratio_half_of_half_byte);
	RUN_TEST_CASE(test_mem_buddy, external_frag_ratio_one_of_four_three_of_eight);
	RUN_TEST_CASE(test_mem_buddy, external_frag_ratio_random);
}
#endif

#ifndef CONFIG_IOTIVITY_RT

static void RunAllTests(void)
{
#ifdef CONFIG_IOTIVITY_RT_BUDDY_MEM_SYS
	RUN_TEST_GROUP(test_mem_buddy);
#endif
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
