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
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include "unity.h"
#include "unity_fixture.h"
#include "rt_transport.h"
#include "ocf_types.h"
#include "ocf_resources.h"
#include "rt_logger.h"
#include "test_common.h"

#define TAG "TC_TRANSPORT"

static ocf_persistent_storage_handler_s temp_doxm_handler = { test_doxm_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_cred_handler = { test_cred_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_acl2_handler = { test_acl2_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_pstat_handler = { test_pstat_fopen, fread, fwrite, fclose };

TEST_GROUP(test_transport);

TEST_SETUP(test_transport)
{
	create_security_data_files();
	ocf_sec_register_ps_handler(&temp_doxm_handler, &temp_pstat_handler, &temp_cred_handler, &temp_acl2_handler);	
	ocf_init(OCF_CLIENT_SERVER, "Samsung", "1.0");
}

TEST_TEAR_DOWN(test_transport)
{
	ocf_terminate();
	remove_security_data_files();
}

TEST(test_transport, rt_udp_get_secure_port_v4)
{
	// given
	uint16_t port_v4 = 0;

	// when
	ocf_result_t result = rt_udp_get_secure_port_v4(&port_v4);

	// then
	TEST_ASSERT_EQUAL_INT(OCF_OK, result);
}

TEST(test_transport, rt_udp_get_normal_port_v4)
{
	// given
	uint16_t port_v4 = 0;

	// when
	ocf_result_t result = rt_udp_get_normal_port_v4(&port_v4);

	// then
	TEST_ASSERT_EQUAL_INT(OCF_OK, result);
}

TEST(test_transport, rt_tcp_get_secure_port_v4)
{
	// given
	uint16_t port_v4 = 0;

	// when
	ocf_result_t result = rt_tcp_get_secure_port_v4(&port_v4);

	// then
	TEST_ASSERT_EQUAL_INT(OCF_OK, result);
}

TEST(test_transport, rt_tcp_get_normal_port_v4)
{
	// given
	uint16_t port_v4 = 0;

	// when
	ocf_result_t result = rt_tcp_get_normal_port_v4(&port_v4);

	// then
	TEST_ASSERT_EQUAL_INT(OCF_OK, result);
}

TEST(test_transport, rt_get_ports_v4)
{
	// given
	uint16_t udp_normal_port_v4, udp_secure_port_v4, tcp_normal_port_v4, tcp_secure_port_v4 = 0;

	// when
	ocf_result_t result = rt_get_ports_v4(&udp_normal_port_v4, &udp_secure_port_v4, &tcp_normal_port_v4, &tcp_secure_port_v4);

	// then
	TEST_ASSERT_EQUAL_INT(OCF_OK, result);
}

TEST(test_transport, rt_get_ports_v4_null)
{
	// given

	// when
	ocf_result_t result = rt_get_ports_v4(NULL, NULL, NULL, NULL);

	// then
	TEST_ASSERT_EQUAL_INT(OCF_OK, result);
}

TEST(test_transport, rt_transport_get_local_ipv4)
{
	// given
	char buf[20] = { 0, };

	// when
	ocf_result_t result = rt_transport_get_local_ipv4(buf, 20);

	// then
	TEST_ASSERT_EQUAL_INT(OCF_OK, result);
}

TEST_GROUP_RUNNER(test_transport)
{
	RUN_TEST_CASE(test_transport, rt_udp_get_secure_port_v4);
	RUN_TEST_CASE(test_transport, rt_udp_get_normal_port_v4);
	RUN_TEST_CASE(test_transport, rt_tcp_get_secure_port_v4);
	RUN_TEST_CASE(test_transport, rt_tcp_get_normal_port_v4);
	RUN_TEST_CASE(test_transport, rt_get_ports_v4);
	RUN_TEST_CASE(test_transport, rt_get_ports_v4_null);
	RUN_TEST_CASE(test_transport, rt_transport_get_local_ipv4);
}

#ifndef CONFIG_ENABLE_RT_OCF

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_transport);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
