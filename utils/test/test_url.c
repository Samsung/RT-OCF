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
#include "rt_url.h"

TEST_GROUP(test_url);

TEST_SETUP(test_url)
{
	rt_mem_pool_init();
}

TEST_TEAR_DOWN(test_url)
{
	rt_mem_pool_terminate();
}

TEST(test_url, url_parse)
{
	char *str[] = {
		"coap://192.168.1.1:3333/oic/res?if=oic.if.baseline",
		"coap+tcp://192.168.1.2:4444/oic/d",
		NULL
	};

	rt_url_field_s *url1 = rt_url_parse(str[0]);
	TEST_ASSERT_EQUAL_STRING("coap://192.168.1.1:3333/oic/res?if=oic.if.baseline", url1->href);
	TEST_ASSERT_EQUAL_STRING("coap", url1->schema);
	TEST_ASSERT_EQUAL_STRING("192.168.1.1", url1->host);
	TEST_ASSERT_EQUAL_STRING("3333", url1->port);
	TEST_ASSERT_EQUAL_STRING("oic/res", url1->path);
	TEST_ASSERT_EQUAL_STRING("if", url1->query_list.query[0].name);
	TEST_ASSERT_EQUAL_STRING("oic.if.baseline", url1->query_list.query[0].value);

	rt_url_field_s *url2 = rt_url_parse(str[1]);
	TEST_ASSERT_EQUAL_STRING("coap+tcp://192.168.1.2:4444/oic/d", url2->href);
	TEST_ASSERT_EQUAL_STRING("coap+tcp", url2->schema);
	TEST_ASSERT_EQUAL_STRING("192.168.1.2", url2->host);
	TEST_ASSERT_EQUAL_STRING("4444", url2->port);
	TEST_ASSERT_EQUAL_STRING("oic/d", url2->path);

	rt_url_free(url1);
	rt_url_free(url2);
}

TEST(test_url, query_parse)
{
	char *query = "if=oic.if.baseline&rt=oic.wk.d&a=1&b=2&c=3";

	ocf_query_list_s query_list = { 0, };

	rt_parse_query(&query_list, query, strlen(query));

	TEST_ASSERT_EQUAL_INT(5, query_list.query_num);
	TEST_ASSERT_EQUAL_STRING("if", query_list.query[0].name);
	TEST_ASSERT_EQUAL_STRING("oic.if.baseline", query_list.query[0].value);
	TEST_ASSERT_EQUAL_STRING("a", query_list.query[2].name);
	TEST_ASSERT_EQUAL_STRING("1", query_list.query[2].value);
	TEST_ASSERT_EQUAL_STRING("c", query_list.query[4].name);
	TEST_ASSERT_EQUAL_STRING("3", query_list.query[4].value);

	rt_query_free(&query_list);
}

TEST_GROUP_RUNNER(test_url)
{
	RUN_TEST_CASE(test_url, url_parse);
	RUN_TEST_CASE(test_url, query_parse);
}

#ifndef CONFIG_ENABLE_RT_OCF
static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_url);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}
#endif
