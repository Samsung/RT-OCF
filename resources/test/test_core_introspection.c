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

#include <fcntl.h>
#include "unity.h"
#include "unity_fixture.h"
#include "rt_resources_manager.h"
#include "rt_logger.h"
#include "rt_core.h"
#include "rt_coap.h"
#include "rt_rep.h"
#include "rt_uuid.h"
#include "rt_utils.h"
#include "test_common.h"
#include "ocf_resources.h"

#define TAG "TC_OIC_INTROSPECTION"

static pthread_cond_t g_condition;
static pthread_mutex_t g_mutex;

static ocf_persistent_storage_handler_s temp_doxm_handler = { test_doxm_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_cred_handler = { test_cred_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_acl2_handler = { test_acl2_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_pstat_handler = { test_pstat_fopen, fread, fwrite, fclose };

TEST_GROUP(test_core_introspection);

TEST_SETUP(test_core_introspection)
{
	pthread_mutex_init(&g_mutex, NULL);
	pthread_cond_init(&g_condition, NULL);
	create_security_data_files();
	ocf_sec_register_ps_handler(&temp_doxm_handler, &temp_pstat_handler, &temp_cred_handler, &temp_acl2_handler);
	ocf_init(OCF_CLIENT_SERVER, "Samsung", OCF_SH_100);
}

TEST_TEAR_DOWN(test_core_introspection)
{
	pthread_cond_destroy(&g_condition);
	pthread_mutex_destroy(&g_mutex);
	ocf_terminate();
	remove_security_data_files();
}

static void response_get_introspection_cb(ocf_rep_decoder_s param_rep, ocf_response_result_t code)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	RT_VERIFY_NON_NULL_VOID(param_rep, TAG, "rep(cbor data) is null");

	pthread_mutex_lock(&g_mutex);

	pthread_cond_signal(&g_condition);
	pthread_mutex_unlock(&g_mutex);
	RT_LOG_D(TAG, "OUT : %s", __func__);
}

TEST(test_core_introspection, check_core_introspection_response_is_valid)
{
	// When
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 5683, OCF_UDP | OCF_IPV4);	// TODO: Should add OCF_SECURE;

	rt_request_get_send(&endpoint, "/introspection", NULL, true, response_get_introspection_cb);

	// Then
	TEST_ASSERT_EQUAL_INT(0, wait_for_condition(&g_mutex, &g_condition));
}

TEST_GROUP_RUNNER(test_core_introspection)
{
	RUN_TEST_CASE(test_core_introspection, check_core_introspection_response_is_valid);
}

#ifndef CONFIG_ENABLE_RT_OCF

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_core_introspection);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
