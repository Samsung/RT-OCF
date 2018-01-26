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
#include "rt_resources_manager.h"
#include "rt_logger.h"
#include "rt_core.h"
#include "rt_coap.h"
#include "rt_rep.h"
#include "rt_utils.h"
#include "test_common.h"
#include "ocf_resources.h"

#define TAG "TC_OIC_RES"
#define MAX_LENGTH 1024

static pthread_cond_t g_condition;
static pthread_mutex_t g_mutex;

static ocf_result_t actual_result = OCF_ERROR;

static ocf_persistent_storage_handler_s temp_doxm_handler = { test_doxm_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_cred_handler = { test_cred_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_acl2_handler = { test_acl2_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_pstat_handler = { test_pstat_fopen, fread, fwrite, fclose };

TEST_GROUP(test_core_resource_with_ocf_init);

TEST_SETUP(test_core_resource_with_ocf_init)
{
	actual_result = OCF_ERROR;
	create_security_data_files();
	ocf_sec_register_ps_handler(&temp_doxm_handler, &temp_pstat_handler, &temp_cred_handler, &temp_acl2_handler);
	ocf_init(OCF_CLIENT_SERVER, "Samsung", OCF_RES_100);
	pthread_mutex_init(&g_mutex, NULL);
	pthread_cond_init(&g_condition, NULL);

}

TEST_TEAR_DOWN(test_core_resource_with_ocf_init)
{
	actual_result = OCF_ERROR;
	pthread_cond_destroy(&g_condition);
	pthread_mutex_destroy(&g_mutex);
	ocf_terminate();
	remove_security_data_files();
}

enum {
	INDEX_DEVICE = 0,
	INDEX_PLATFORM
};

static void response_discovery_cb(ocf_rep_decoder_s param_rep, ocf_response_result_t code)
{

	pthread_mutex_lock(&g_mutex);
	if (!param_rep) {
		goto exit;
	}

	rt_rep_decoder_s *rep = (rt_rep_decoder_s *) param_rep;

	int i;

	size_t length;
	uint16_t array_len1 = 0;
	rt_rep_decoder_s map1;

	if (rt_rep_get_array_length(rep, &array_len1) != OCF_OK) {
		goto exit;
	}

	char str[MAX_LENGTH];

	uint8_t count_array[2] = { 0, 0 };
	uint8_t expected_array[2] = { 1, 1 };

	for (i = 0; i < array_len1; ++i) {
		rt_rep_get_map_from_array(rep, i, &map1);
		rt_rep_get_string_length_from_map(&map1, "href", &length);

		if ((strlen(CORE_P) != length) && (strlen(CORE_D) != length)) {
			continue;
		}
		rt_rep_get_string_from_map(&map1, "href", str);

		if (0 == strncmp(CORE_P, str, sizeof(CORE_P))) {
			count_array[INDEX_PLATFORM]++;
		} else if (0 == strncmp(CORE_D, str, sizeof(CORE_D))) {
			count_array[INDEX_DEVICE]++;
		}
	}

	if ((count_array[0] == expected_array[0]) && (count_array[1] == expected_array[1])) {
		actual_result = OCF_OK;
	}

exit:
	pthread_cond_signal(&g_condition);
	pthread_mutex_unlock(&g_mutex);

}

TEST(test_core_resource_with_ocf_init, check_core_res_response_is_valid)
{
	// When
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 5683, OCF_UDP | OCF_IPV4);	// TODO: Should add OCF_SECURE;

	rt_request_get_send(&endpoint, CORE_RES, NULL, true, response_discovery_cb);

	wait_for_condition(&g_mutex, &g_condition);
	// wait
	TEST_ASSERT_EQUAL_INT(OCF_OK, actual_result);
}

static void response_discovery_cb_with_baseline(ocf_rep_decoder_s param_rep, ocf_response_result_t code)
{

	pthread_mutex_lock(&g_mutex);

	if (!param_rep) {
		goto exit;
	}

	rt_rep_decoder_s *rep = (rt_rep_decoder_s *) param_rep;
	rt_rep_decoder_s map1;

	uint16_t array_len1 = 0;

	// I'm curious whether receiving array is correct or not
	if (rt_rep_get_array_length(rep, &array_len1) != OCF_OK) {
		goto exit;
	}

	if (array_len1 != 1) {
		goto exit;
	}

	if (rt_rep_get_map_from_array(rep, 0, &map1) != OCF_OK) {
		goto exit;
	}

	rt_rep_decoder_s array;

	if (rt_rep_get_array_from_map(&map1, "links", &array) != OCF_OK) {
		goto exit;
	}

	actual_result = OCF_OK;

exit:
	pthread_cond_signal(&g_condition);
	pthread_mutex_unlock(&g_mutex);

}

TEST(test_core_resource_with_ocf_init, check_core_res_response_with_baseline_is_valid)
{
	// When
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 5683, OCF_UDP | OCF_IPV4);	// TODO: Should add OCF_SECURE;

	rt_request_get_send(&endpoint, CORE_RES, "if=oic.if.baseline", true, response_discovery_cb_with_baseline);

	wait_for_condition(&g_mutex, &g_condition);

	TEST_ASSERT_EQUAL_INT(OCF_OK, actual_result);
}

#define RES_DISCOVERABLE "/a/light_set_discoverable"
#define RES_UNDISCOVERABLE "/a/light_unset_discoverable"

enum {
	INDEX_RES_DISCOVERABLE = 0,
	INDEX_RES_UNDISCOVERABLE
};

static void check_discoverable_resources_cb(ocf_rep_decoder_s param_rep, ocf_response_result_t code)
{
	pthread_mutex_lock(&g_mutex);

	if (!param_rep) {
		goto exit;
	}

	rt_rep_decoder_s *rep = (rt_rep_decoder_s *) param_rep;
	int i;

	size_t length;
	uint16_t array_len1 = 0;
	rt_rep_decoder_s map1;

	if (rt_rep_get_array_length(rep, &array_len1) != OCF_OK) {
		goto exit;
	}

	char str[MAX_LENGTH];

	uint8_t count_array[2] = { 0, 0 };
	uint8_t expected_array[2] = { 1, 0 };

	for (i = 0; i < array_len1; ++i) {

		rt_rep_get_map_from_array(rep, i, &map1);
		rt_rep_get_string_length_from_map(&map1, "href", &length);

		rt_rep_get_string_from_map(&map1, "href", str);

		if (0 == strncmp(RES_DISCOVERABLE, str, sizeof(RES_DISCOVERABLE))) {
			count_array[INDEX_RES_DISCOVERABLE]++;
		} else if (0 == strncmp(RES_UNDISCOVERABLE, str, sizeof(RES_UNDISCOVERABLE))) {
			count_array[INDEX_RES_UNDISCOVERABLE]++;
		}
	}

	RT_LOG_E(TAG, " cnt_array+ %d, %d", count_array[0], count_array[1]);

	if ((count_array[0] == expected_array[0]) && (count_array[1] == expected_array[1])) {
		actual_result = OCF_OK;
	}

exit:
	pthread_cond_signal(&g_condition);
	pthread_mutex_unlock(&g_mutex);

}

TEST(test_core_resource_with_ocf_init, check_discoverable_resources)
{
	// Given
	rt_resource_s *discoverable_res = rt_res_new_resource(RES_DISCOVERABLE);
	rt_res_set_discoverable(discoverable_res, true);
	const char *str_types[1] = { "oic.r.light" };
	rt_res_set_resource_types(discoverable_res, str_types, 1);
	rt_res_register_resource(discoverable_res);

	rt_resource_s *undiscoverable_res = rt_res_new_resource(RES_UNDISCOVERABLE);
	rt_res_set_discoverable(undiscoverable_res, false);
	const char *str_types2[1] = { "oic.r.light" };
	rt_res_set_resource_types(undiscoverable_res, str_types2, 1);
	rt_res_register_resource(undiscoverable_res);

	// When
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 5683, OCF_UDP | OCF_IPV4);	// TODO: Should add OCF_SECURE;
	rt_request_get_send(&endpoint, CORE_RES, NULL, true, check_discoverable_resources_cb);

	// wait
	wait_for_condition(&g_mutex, &g_condition);

	TEST_ASSERT_EQUAL_INT(OCF_OK, actual_result);

}

static void check_invalid_rt_query_cb(ocf_rep_decoder_s param_rep, ocf_response_result_t code)
{
	pthread_mutex_lock(&g_mutex);
	RT_LOG_F(TAG, "OCF RESPONSE: %d", code);

	if (code == OCF_RESPONSE_RESOURCE_NOT_FOUND) {
		actual_result = OCF_OK;
	}

	pthread_cond_signal(&g_condition);
	pthread_mutex_unlock(&g_mutex);

}

TEST(test_core_resource_with_ocf_init, discovery_with_invalid_rt_query)
{
	// Given
	rt_resource_s *discoverable_res = rt_res_new_resource(RES_DISCOVERABLE);
	rt_res_set_discoverable(discoverable_res, true);
	const char *str_types[1] = { "oic.r.light" };
	rt_res_set_resource_types(discoverable_res, str_types, 1);
	rt_res_register_resource(discoverable_res);

	// When
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 5683, OCF_UDP | OCF_IPV4);	// TODO: Should add OCF_SECURE;
	rt_request_get_send(&endpoint, CORE_RES, "rt=invalid", true, check_invalid_rt_query_cb);

	// wait & then
	wait_for_condition(&g_mutex, &g_condition);
	TEST_ASSERT_EQUAL_INT(OCF_OK, actual_result);
}

static void check_discoverable_resources_ocf_1_0_cb(ocf_rep_decoder_s param_rep, ocf_response_result_t code)
{
	pthread_mutex_lock(&g_mutex);

	if (!param_rep) {
		goto exit;
	}
	uint16_t array_len1 = 0;
	rt_rep_decoder_s *rep = (rt_rep_decoder_s *) param_rep;

	if (rt_rep_get_array_length(rep, &array_len1) != OCF_OK) {
		goto exit;
	}

	char str[MAX_LENGTH];
	rt_rep_decoder_s map1;
	int i;
	for (i = 0; i < array_len1; ++i) {
		rt_rep_get_map_from_array(rep, i, &map1);
		if (rt_rep_get_string_from_map(&map1, "anchor", str) != OCF_OK) {
			goto exit;
		}

	}
	actual_result = OCF_OK;

exit:
	pthread_cond_signal(&g_condition);
	pthread_mutex_unlock(&g_mutex);
}

TEST(test_core_resource_with_ocf_init, check_discoverable_resources_ocf_1_0)
{
	// Given
	rt_resource_s *discoverable_res = rt_res_new_resource(RES_DISCOVERABLE);
	rt_res_set_discoverable(discoverable_res, true);
	const char *str_types[1] = { "oic.r.light" };
	rt_res_set_resource_types(discoverable_res, str_types, 1);
	rt_res_register_resource(discoverable_res);

	rt_resource_s *undiscoverable_res = rt_res_new_resource(RES_UNDISCOVERABLE);
	rt_res_set_discoverable(undiscoverable_res, false);
	const char *str_types2[1] = { "oic.r.light" };
	rt_res_set_resource_types(undiscoverable_res, str_types2, 1);
	rt_res_register_resource(undiscoverable_res);

	// When
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 5683, OCF_UDP | OCF_IPV4);	// TODO: Should add OCF_SECURE;
	ocf_request_get_send(&endpoint, CORE_RES, NULL, true, check_discoverable_resources_ocf_1_0_cb);

	wait_for_condition(&g_mutex, &g_condition);
	// wait
	TEST_ASSERT_EQUAL_INT(OCF_OK, actual_result);
}

TEST_GROUP_RUNNER(test_core_resource_with_ocf_init)
{
	RUN_TEST_CASE(test_core_resource_with_ocf_init, check_core_res_response_is_valid);
	RUN_TEST_CASE(test_core_resource_with_ocf_init, check_core_res_response_with_baseline_is_valid);
	RUN_TEST_CASE(test_core_resource_with_ocf_init, check_discoverable_resources);
	RUN_TEST_CASE(test_core_resource_with_ocf_init, discovery_with_invalid_rt_query);
	RUN_TEST_CASE(test_core_resource_with_ocf_init, check_discoverable_resources_ocf_1_0);

}

#ifndef CONFIG_ENABLE_RT_OCF

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_core_resource_with_ocf_init);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
