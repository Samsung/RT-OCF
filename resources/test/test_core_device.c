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

#define TAG "TC_OIC_D"

static const char expectedUUID[RT_UUID_STR_LEN] = "61646d69-6e44-6576-6963-655575696430";

static pthread_cond_t g_condition;
static pthread_mutex_t g_mutex;

static ocf_persistent_storage_handler_s temp_doxm_handler = { test_doxm_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_cred_handler = { test_cred_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_acl2_handler = { test_acl2_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_pstat_handler = { test_pstat_fopen, fread, fwrite, fclose };

TEST_GROUP(test_core_device);

TEST_SETUP(test_core_device)
{
	pthread_mutex_init(&g_mutex, NULL);
	pthread_cond_init(&g_condition, NULL);
	create_security_data_files();
	ocf_sec_register_ps_handler(&temp_doxm_handler, &temp_pstat_handler, &temp_cred_handler, &temp_acl2_handler);
	ocf_init(OCF_CLIENT_SERVER, "Samsung", OCF_SH_100);
}

TEST_TEAR_DOWN(test_core_device)
{
	pthread_cond_destroy(&g_condition);
	pthread_mutex_destroy(&g_mutex);
	ocf_terminate();
	remove_security_data_files();
}

static void response_get_device_cb(ocf_rep_decoder_s param_rep, ocf_response_result_t code)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	RT_VERIFY_NON_NULL_VOID(param_rep, TAG, "rep(cbor data) is null");

	rt_rep_decoder_s *rep = (rt_rep_decoder_s *) param_rep;
	pthread_mutex_lock(&g_mutex);

	char deviceUUID[RT_UUID_STR_LEN];
	rt_rep_get_string_from_map(rep, "di", deviceUUID);
	char dataModelVersion[40];
	rt_rep_get_string_from_map(rep, "dmv", dataModelVersion);
	char deviceName[20];
	rt_rep_get_string_from_map(rep, "n", deviceName);

	rt_rep_decoder_s device_types[1];
	rt_rep_get_array_from_map(rep, OIC_RT_NAME, device_types);

	int i;
	uint16_t type_count, actual_type_count = 0;
	char device_type[256];
	
	rt_rep_get_array_length(device_types, &type_count);

	for (i = 0; i < type_count; ++i) {
		rt_rep_get_string_from_array(device_types, i, device_type);
		if (0 == strncmp("oic.wk.d", device_type, sizeof("oic.wk.d"))) {
			actual_type_count++;
		}
		if (0 == strncmp("oic.d.light", device_type, sizeof("oic.d.light"))) {
			actual_type_count++;
		}
	}

	TEST_ASSERT_EQUAL_INT(2, actual_type_count);
	TEST_ASSERT_EQUAL_STRING(expectedUUID, deviceUUID);
	TEST_ASSERT_EQUAL_STRING(OCF_SH_100_VALUE, dataModelVersion);
	TEST_ASSERT_EQUAL_STRING("Airconditioner", deviceName);
	pthread_cond_signal(&g_condition);
	pthread_mutex_unlock(&g_mutex);
	RT_LOG_D(TAG, "OUT : %s", __func__);
}

TEST(test_core_device, check_core_d_response_is_valid)
{
	// Given
	rt_core_set_oic_d_name_opt("Airconditioner");
	const char *device_types[1] = { "oic.d.light" };
	rt_core_add_oic_d_type(device_types, 1);

	// When
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 5683, OCF_UDP | OCF_IPV4);	// TODO: Should add OCF_SECURE;

	rt_request_get_send(&endpoint, CORE_D, NULL, true, response_get_device_cb);

	// Then
	TEST_ASSERT_EQUAL_INT(0, wait_for_condition(&g_mutex, &g_condition));
}

TEST_GROUP_RUNNER(test_core_device)
{
	RUN_TEST_CASE(test_core_device, check_core_d_response_is_valid);
}

#ifndef CONFIG_IOTIVITY_RT

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_core_device);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
