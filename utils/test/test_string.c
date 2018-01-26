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

#include "rt_string.h"
#include <string.h>

#define LENGTH 10

TEST_GROUP(test_string);

TEST_SETUP(test_string)
{
}

TEST_TEAR_DOWN(test_string)
{
}

TEST(test_string, whole_replacement)
{
	char expected[LENGTH] = "123456";;
	char src[LENGTH] = "123456";
	char dest[LENGTH];

	rt_strncpy(dest, src, strlen(src));

	TEST_ASSERT_EQUAL_STRING(expected, dest);
}

TEST(test_string, part_replacement)
{
	int len;
	char src[LENGTH] = "123";
	char dest1[LENGTH] = "abcdefghij";
	char dest2[LENGTH] = "abcdefghij";

	len = strlen(src);

	strncpy(dest1, src, len);
	rt_strncpy(dest2, src, len);

	TEST_ASSERT_NOT_EQUAL(strlen(dest1), strlen(dest2));
}

TEST(test_string, dest_null_error)
{
	char src[LENGTH] = "123";
	char *dest = NULL;

	TEST_ASSERT_EQUAL(NULL, rt_strncpy(dest, src, strlen(src)));
}

TEST(test_string, src_null_returns_dest)
{

	char expected[LENGTH] = "abc";
	char *src = NULL;
	char dest[LENGTH] = "abc";

	TEST_ASSERT_EQUAL_STRING(expected, rt_strncpy(dest, src, LENGTH));

}

TEST(test_string, len_zero_returns_dest)
{

	char expected[LENGTH] = "abc";
	char src[LENGTH] = "1234";
	char dest[LENGTH] = "abc";

	TEST_ASSERT_EQUAL_STRING(expected, rt_strncpy(dest, src, 0));
}

TEST(test_string, basic_test_rt_strcpy)
{

	char expected[LENGTH] = "1234";
	char src[LENGTH] = "1234";
	char dest[LENGTH] = "a";

	TEST_ASSERT_EQUAL_STRING(expected, rt_strcpy(dest, src));
}

TEST_GROUP_RUNNER(test_string)
{

	RUN_TEST_CASE(test_string, whole_replacement);
	RUN_TEST_CASE(test_string, part_replacement);
	RUN_TEST_CASE(test_string, dest_null_error);
	RUN_TEST_CASE(test_string, len_zero_returns_dest);
	RUN_TEST_CASE(test_string, src_null_returns_dest);
	RUN_TEST_CASE(test_string, basic_test_rt_strcpy);
}

#ifndef CONFIG_ENABLE_RT_OCF
static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_string);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}
#endif
