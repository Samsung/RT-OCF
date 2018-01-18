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

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include "unity.h"
#include "unity_fixture.h"
#include "ocf_types.h"
#include "rt_logger.h"
#include "rt_endpoint.h"
#include "test_common.h"
#include "ocf_resources.h"

static ocf_persistent_storage_handler_s temp_doxm_handler = { test_doxm_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_cred_handler = { test_cred_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_acl2_handler = { test_acl2_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_pstat_handler = { test_pstat_fopen, fread, fwrite, fclose };

TEST_GROUP(test_endpoint);

TEST_SETUP(test_endpoint)
{
	create_security_data_files();
	ocf_sec_register_ps_handler(&temp_doxm_handler, &temp_pstat_handler, &temp_cred_handler, &temp_acl2_handler);
	ocf_init(OCF_CLIENT_SERVER, "Samsung", "1.0");
}

TEST_TEAR_DOWN(test_endpoint)
{
	ocf_terminate();
	remove_security_data_files();
}

TEST(test_endpoint, rt_endpoint_set)
{
	// given
	ocf_endpoint_s endpoint;

	// when

	// then
	TEST_ASSERT_EQUAL_INT(OCF_OK, rt_endpoint_set(&endpoint, "127.0.0.1", 5555, OCF_IPV4));
}

TEST(test_endpoint, rt_endpoint_set_null_endpoint)
{
	// given
	// when
	// then
	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, rt_endpoint_set(NULL, "127.0.0.1", 5555, OCF_IPV4));
}

TEST(test_endpoint, rt_endpoint_set_unsupported_flag)
{
	// given
	ocf_endpoint_s actual;

	// when
	// then
	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, rt_endpoint_set(&actual, "127.0.0.1", 5555, OCF_IPV6));
}

TEST(test_endpoint, rt_endpoint_is_equal_ipv4_return_true)
{
	// given
	ocf_endpoint_s endpoint1, endpoint2;

	// when
	rt_endpoint_set(&endpoint1, "127.0.0.1", 5555, OCF_IPV4);
	rt_endpoint_set(&endpoint2, "127.0.0.1", 5555, OCF_IPV4);

	// then
	TEST_ASSERT_TRUE(rt_endpoint_is_equal(&endpoint1, &endpoint2));
}

TEST(test_endpoint, rt_endpoint_is_equal_ipv4_return_false_with_ip)
{
	// given
	ocf_endpoint_s endpoint1, endpoint2;

	// when
	rt_endpoint_set(&endpoint1, "127.0.0.1", 5555, OCF_IPV4);
	rt_endpoint_set(&endpoint2, "127.0.0.0", 5555, OCF_IPV4);

	// then
	TEST_ASSERT_FALSE(rt_endpoint_is_equal(&endpoint1, &endpoint2));
}

TEST(test_endpoint, rt_endpoint_is_equal_ipv4_return_false_with_port)
{
	// given
	ocf_endpoint_s endpoint1, endpoint2;

	// when
	rt_endpoint_set(&endpoint1, "127.0.0.1", 5555, OCF_IPV4);
	rt_endpoint_set(&endpoint2, "127.0.0.1", 5554, OCF_IPV4);

	// then
	TEST_ASSERT_FALSE(rt_endpoint_is_equal(&endpoint1, &endpoint2));
}

TEST(test_endpoint, rt_endpoint_is_equal_with_null_endpoint_return_false)
{
	// given
	ocf_endpoint_s endpoint;

	// when
	rt_endpoint_set(&endpoint, "127.0.0.1", 5555, OCF_IPV4);

	// then
	TEST_ASSERT_FALSE(rt_endpoint_is_equal(&endpoint, NULL));
}

TEST(test_endpoint, rt_endpoint_is_equal_with_different_ip_flags_return_false)
{
	// given
	ocf_endpoint_s endpoint1, endpoint2;

	// when
	rt_endpoint_set(&endpoint1, "127.0.0.1", 5555, OCF_IPV4);
	rt_endpoint_set(&endpoint2, "127.0.0.1", 5554, OCF_IPV6);

	// then
	TEST_ASSERT_FALSE(rt_endpoint_is_equal(&endpoint1, &endpoint2));
}

TEST(test_endpoint, rt_endpoint_is_equal_ipv4_check_changedip_return_true)
{
	// given
	ocf_endpoint_s endpoint1;
	ocf_endpoint_s endpoint2;

	memset(&endpoint1, 0, sizeof(ocf_endpoint_s));
	inet_pton(AF_INET, "127.0.0.1", &(endpoint1.addr[0]));
	endpoint1.port = 5555;
	endpoint1.flags = OCF_IPV4;

	// when
	rt_endpoint_set(&endpoint2, "127.0.0.1", 5555, OCF_IPV4);

	// then
	TEST_ASSERT_TRUE(rt_endpoint_is_equal(&endpoint1, &endpoint2));
}

TEST(test_endpoint, rt_transport_ipv4_str_reverse)
{
	// given
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 5555, OCF_IPV4);

	// when
	char buf[20];
	inet_ntop(AF_INET, &(endpoint.addr[0]), buf, sizeof(buf));

	// then
	TEST_ASSERT_EQUAL_INT(0, strncmp("127.0.0.1", buf, sizeof("127.0.0.1")));

}

TEST(test_endpoint, rt_endpoint_get_addr_str)
{
	// given
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 5555, OCF_IPV4);

	// when
	char buf[20];
	rt_endpoint_get_addr_str(&endpoint, buf, sizeof(buf));

	// then
	TEST_ASSERT_EQUAL_INT(0, strncmp("127.0.0.1", buf, sizeof("127.0.0.1")));

}

TEST(test_endpoint, rt_endpoint_log)
{
	// given
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 5555, OCF_IPV4);

	// when
	rt_endpoint_log(OCF_LOG_DEBUG, "TC_TRANSPORT", &endpoint);

	// then

}

TEST(test_endpoint, rt_endpoint_log_null)
{
	// given

	// when
	rt_endpoint_log(OCF_LOG_DEBUG, "TC_TRANSPORT", NULL);

	// then
}

TEST(test_endpoint, rt_endpoint_get_flags_from_ep_for_coap)
{
	// given
	char *url = "coap://10.112.161.54:52516";
	ocf_transport_flags_t flags = 0;
	ocf_transport_flags_t expected_flags = 0;
	expected_flags = OCF_IPV4 | OCF_UDP;

	rt_url_field_s *parse_url = rt_url_parse(url);

	// when
	ocf_result_t ret = rt_endpoint_get_flags(parse_url, &flags);
	rt_url_free(parse_url);

	// then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_INT(expected_flags, flags);
}

TEST(test_endpoint, rt_endpoint_get_flags_from_ep_for_coaps)
{
	// given
	char *url = "coaps://10.112.161.54:52516";
	ocf_transport_flags_t flags = 0;
	ocf_transport_flags_t expected_flags = 0;
	expected_flags = OCF_IPV4 | OCF_UDP | OCF_SECURE;

	rt_url_field_s *parse_url = rt_url_parse(url);
	
	// when
	ocf_result_t ret = rt_endpoint_get_flags(parse_url, &flags);
	rt_url_free(parse_url);

	// then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_INT(expected_flags, flags);
}

TEST(test_endpoint, rt_endpoint_get_flags_from_ep_for_coap_tcp)
{
	// given
	char *url = "coap+tcp://10.112.161.54:52516";
	ocf_transport_flags_t flags = 0;
	ocf_transport_flags_t expected_flags = 0;
	expected_flags = OCF_IPV4 | OCF_TCP;

	rt_url_field_s *parse_url = rt_url_parse(url);

	// when
	ocf_result_t ret = rt_endpoint_get_flags(parse_url, &flags);
	rt_url_free(parse_url);

	// then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_INT(expected_flags, flags);
}

TEST(test_endpoint, rt_endpoint_get_flags_from_ep_for_coaps_tcp)
{
	// given
	char *url = "coaps+tcp://10.112.161.54:52516";
	ocf_transport_flags_t flags = 0;
	ocf_transport_flags_t expected_flags = 0;
	expected_flags = OCF_IPV4 | OCF_TCP | OCF_SECURE;

	rt_url_field_s *parse_url = rt_url_parse(url);
	
	// when
	ocf_result_t ret = rt_endpoint_get_flags(parse_url, &flags);
	rt_url_free(parse_url);

	// then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_INT(expected_flags, flags);
}

TEST(test_endpoint, rt_endpoint_get_flags_from_ep_for_coaps_tcp_ipv6)
{
	// given
	char *url = "coaps+tcp://[fe80::ef68:a0c8:4006:20d8/64]:52516";
	ocf_transport_flags_t flags = 0;
	ocf_transport_flags_t expected_flags = 0;
	expected_flags = OCF_IPV6 | OCF_TCP | OCF_SECURE;

	rt_url_field_s *parse_url = rt_url_parse(url);
	
	// when
	ocf_result_t ret = rt_endpoint_get_flags(parse_url, &flags);
	rt_url_free(parse_url);

	// then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_INT(expected_flags, flags);
}

TEST_GROUP_RUNNER(test_endpoint)
{
	RUN_TEST_CASE(test_endpoint, rt_endpoint_set);
	RUN_TEST_CASE(test_endpoint, rt_endpoint_set_null_endpoint);
	RUN_TEST_CASE(test_endpoint, rt_endpoint_set_unsupported_flag);
	RUN_TEST_CASE(test_endpoint, rt_endpoint_is_equal_ipv4_return_true);
	RUN_TEST_CASE(test_endpoint, rt_endpoint_is_equal_ipv4_return_false_with_ip);
	RUN_TEST_CASE(test_endpoint, rt_endpoint_is_equal_ipv4_return_false_with_port);
	RUN_TEST_CASE(test_endpoint, rt_endpoint_is_equal_with_null_endpoint_return_false);
	RUN_TEST_CASE(test_endpoint, rt_endpoint_is_equal_with_different_ip_flags_return_false);
	RUN_TEST_CASE(test_endpoint, rt_endpoint_is_equal_ipv4_check_changedip_return_true);
	RUN_TEST_CASE(test_endpoint, rt_transport_ipv4_str_reverse);
	RUN_TEST_CASE(test_endpoint, rt_endpoint_get_addr_str);
	RUN_TEST_CASE(test_endpoint, rt_endpoint_log);
	RUN_TEST_CASE(test_endpoint, rt_endpoint_log_null);
	RUN_TEST_CASE(test_endpoint, rt_endpoint_get_flags_from_ep_for_coap);
	RUN_TEST_CASE(test_endpoint, rt_endpoint_get_flags_from_ep_for_coaps);
	RUN_TEST_CASE(test_endpoint, rt_endpoint_get_flags_from_ep_for_coap_tcp);
	RUN_TEST_CASE(test_endpoint, rt_endpoint_get_flags_from_ep_for_coaps_tcp);
	RUN_TEST_CASE(test_endpoint, rt_endpoint_get_flags_from_ep_for_coaps_tcp_ipv6);
}

#ifndef CONFIG_IOTIVITY_RT

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_endpoint);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
