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

#include "ocf_types.h"
#include "ocf_resources.h"
#include "rt_ssl.h"
#include "rt_endpoint.h"
#include "test_common.h"

static ocf_persistent_storage_handler_s temp_doxm_handler = { test_doxm_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_cred_handler = { test_cred_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_acl2_handler = { test_acl2_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_pstat_handler = { test_pstat_fopen, fread, fwrite, fclose };

TEST_GROUP(test_ssl_common);

TEST_SETUP(test_ssl_common)
{
	create_security_data_files();
	ocf_sec_register_ps_handler(&temp_doxm_handler, &temp_pstat_handler, &temp_cred_handler, &temp_acl2_handler);
	ocf_init(OCF_CLIENT_SERVER, "Samsung", "1.0");;
}

TEST_TEAR_DOWN(test_ssl_common)
{
	ocf_terminate();
	remove_security_data_files();
}

TEST(test_ssl_common, ssl_check_session)
{
	// given

	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 5555, OCF_IPV4 | OCF_UDP);

	rt_ssl_state_t ssl_state;

	// when
	rt_ssl_check_session(&endpoint, &ssl_state);

	// then
	TEST_ASSERT_EQUAL_INT(RT_SSL_HANDSHAKE_NON, ssl_state);
}

TEST_GROUP_RUNNER(test_ssl_common)
{
	RUN_TEST_CASE(test_ssl_common, ssl_check_session);
}

#ifndef CONFIG_ENABLE_RT_OCF

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_ssl_common);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
