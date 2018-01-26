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

#if defined(CONFIG_RT_OCF_KERNEL_MEM_SYS)
#include "unity.h"
#include "unity_fixture.h"
#include <stdio.h>
#include "rt_mem.h"
#include "rt_list.h"

static mem_info_s *mem;

TEST_GROUP(test_mem);

TEST_SETUP(test_mem)
{
	mem = getMemInfo();
	rt_mem_pool_init();
}

TEST_TEAR_DOWN(test_mem)
{
	rt_mem_pool_terminate();
}

TEST(test_mem, getMemInfo_default_value)
{
	// Given

	// Then
	TEST_ASSERT_EQUAL_INT(0, mem->peak);
	TEST_ASSERT_EQUAL_INT(0, mem->current);
	TEST_ASSERT_EQUAL_INT(OCF_RT_MEM_POOL_SIZE, mem->total);
}

TEST(test_mem, getMemInfo_alloc_int)
{
	int *a = (int *)rt_mem_alloc(sizeof(int));
	
	//Then
	TEST_ASSERT_EQUAL_INT(4, mem->peak);
	TEST_ASSERT_EQUAL_INT(4, mem->current);
	TEST_ASSERT_EQUAL_INT(OCF_RT_MEM_POOL_SIZE, mem->total);

	rt_mem_free(a);	
}

TEST(test_mem, getMemInfo_detect_leak)
{
	(int *)rt_mem_alloc(sizeof(int));
	
	//Then
	TEST_ASSERT_EQUAL_INT(4, rt_mem_kernel_terminate(mem));
}

TEST(test_mem, getMemInfo_alloc_int_twice)
{
	int *a = (int *)rt_mem_alloc(sizeof(int));
	int *b = (int *)rt_mem_alloc(sizeof(int));

	//Then
	TEST_ASSERT_EQUAL_INT(8, mem->peak);
	TEST_ASSERT_EQUAL_INT(8, mem->current);
	TEST_ASSERT_EQUAL_INT(OCF_RT_MEM_POOL_SIZE, mem->total);

	rt_mem_free(a);
	rt_mem_free(b);
}

TEST(test_mem, getMemInfo_alloc_int_free_one)
{
	int *a = (int *)rt_mem_alloc(sizeof(int));
	int *b = (int *)rt_mem_alloc(sizeof(int));

	rt_mem_free(b);

	TEST_ASSERT_EQUAL_INT(8, mem->peak);
	TEST_ASSERT_EQUAL_INT(4, mem->current);
	TEST_ASSERT_EQUAL_INT(OCF_RT_MEM_POOL_SIZE, mem->total);

	rt_mem_free(a);
}

TEST(test_mem, getMemInfo_alloc_int_double)
{
	int *a = (int *)rt_mem_alloc(sizeof(int));
	double *b = (double *)rt_mem_alloc(sizeof(double));

	TEST_ASSERT_EQUAL_INT(12, mem->peak);
	TEST_ASSERT_EQUAL_INT(12, mem->current);
	TEST_ASSERT_EQUAL_INT(OCF_RT_MEM_POOL_SIZE, mem->total);

	rt_mem_free(a);
	rt_mem_free(b);
}

TEST(test_mem, getMemInfo_alloc_int_double_free_double)
{
	int *a = (int *)rt_mem_alloc(sizeof(int));
	double *d = (double *)rt_mem_alloc(sizeof(double));

	rt_mem_free(d);

	TEST_ASSERT_EQUAL_INT(12, mem->peak);
	TEST_ASSERT_EQUAL_INT(4, mem->current);
	TEST_ASSERT_EQUAL_INT(OCF_RT_MEM_POOL_SIZE, mem->total);

	rt_mem_free(a);
}

TEST(test_mem, getMemAssigendInfo_alloc_int_twice)
{
	int *a = (int *)rt_mem_alloc(sizeof(int));
	uint32_t *b = (uint32_t *) rt_mem_alloc(sizeof(uint32_t));

	//Then
	rt_node_s *itr = mem->kernel_list->head;
	while (itr) {
		mem_assign_info_s *var = (mem_assign_info_s *) rt_list_get_item(mem->kernel_list, itr);
		TEST_ASSERT_EQUAL_INT(4, var->size);
		itr = itr->next;
	}

	rt_mem_free(a);
	rt_mem_free(b);
}

TEST(test_mem, rt_mem_realloc_null)
{
	// Given
	int *a = NULL;

	// When
	a = rt_mem_realloc(a, 10);

	// Then
	TEST_ASSERT_NULL(a);
}

TEST(test_mem, rt_mem_realloc_with_big_size)
{
	// Given
	int *a = rt_mem_alloc(sizeof(int) * 2);
	int *b = NULL;

	a[0] = 10;
	a[1] = 11;

	// When
	b = rt_mem_realloc(a, sizeof(int) * 10);
	b[9] = 3;

	// Then
	TEST_ASSERT_EQUAL_INT(10, b[0]);
	TEST_ASSERT_EQUAL_INT(11, b[1]);
	TEST_ASSERT_EQUAL_INT(0, b[2]);
	TEST_ASSERT_EQUAL_INT(3, b[9]);

	rt_mem_free(b);
}

TEST(test_mem, rt_mem_realloc_with_small_size)
{
	// Given
	int *a = rt_mem_alloc(sizeof(int) * 3);
	int *b = NULL;

	a[0] = 5;
	a[1] = 11;
	a[2] = 12;

	// When
	b = rt_mem_realloc(a, sizeof(int) * 1);

	// Then
	TEST_ASSERT_EQUAL_INT(5, b[0]);

	rt_mem_free(b);
}

TEST_GROUP_RUNNER(test_mem)
{
	RUN_TEST_CASE(test_mem, getMemInfo_default_value);
	RUN_TEST_CASE(test_mem, getMemInfo_alloc_int);
	RUN_TEST_CASE(test_mem, getMemInfo_detect_leak);
	RUN_TEST_CASE(test_mem, getMemInfo_alloc_int_twice);
	RUN_TEST_CASE(test_mem, getMemInfo_alloc_int_free_one);
	RUN_TEST_CASE(test_mem, getMemInfo_alloc_int_double);
	RUN_TEST_CASE(test_mem, getMemInfo_alloc_int_double_free_double);
	RUN_TEST_CASE(test_mem, rt_mem_realloc_null);
	RUN_TEST_CASE(test_mem, rt_mem_realloc_with_big_size);
	RUN_TEST_CASE(test_mem, rt_mem_realloc_with_small_size);
	//RUN_TEST_CASE(test_mem, getMemAssigendInfo_alloc_int_twice);
}
#endif

#ifndef CONFIG_ENABLE_RT_OCF

static void RunAllTests(void)
{
#if defined(CONFIG_RT_OCF_KERNEL_MEM_SYS)
	RUN_TEST_GROUP(test_mem);
#endif
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
