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

#include <pthread.h>
#include "unity.h"
#include "unity_fixture.h"
#include "rt_resources.h"
#include "rt_resources_manager.h"
#include "rt_request.h"
#include "ocf_types.h"
#include "ocf_resources.h"
#include "rt_mem.h"
#include "rt_manager.h"
#include "rt_data_handler.h"
#include "rt_coap.h"
#include "rt_rep.h"
#include "test_common.h"
#include "ocf_resources.h"
#include "rt_logger.h"

#define TAG "TC_RES_MGR"

static pthread_cond_t g_condition;
static pthread_mutex_t g_mutex;

TEST_GROUP(test_resources);

static rt_resource_s *resource;

static ocf_persistent_storage_handler_s temp_doxm_handler = { test_doxm_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_cred_handler = { test_cred_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_acl2_handler = { test_acl2_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_pstat_handler = { test_pstat_fopen, fread, fwrite, fclose };

TEST_SETUP(test_resources)
{
	create_security_data_files();
	ocf_sec_register_ps_handler(&temp_doxm_handler, &temp_pstat_handler, &temp_cred_handler, &temp_acl2_handler);
	ocf_init(OCF_CLIENT_SERVER, "Samsung", OCF_RES_100);
	pthread_mutex_init(&g_mutex, NULL);
	pthread_cond_init(&g_condition, NULL);

}

TEST_TEAR_DOWN(test_resources)
{
	pthread_cond_destroy(&g_condition);
	pthread_mutex_destroy(&g_mutex);
	ocf_terminate();
	remove_security_data_files();
}

TEST(test_resources, rt_res_register_resource_one_resource)
{
	// Given
	rt_resource_s *res = rt_res_new_resource("/a/light");

	// When
	ocf_result_t result = rt_res_register_resource(res);

	// Then
	TEST_ASSERT_EQUAL(res, rt_res_get_resource_by_href("/a/light"));
	TEST_ASSERT_EQUAL_INT(OCF_OK, result);
}

TEST(test_resources, rt_res_register_resource_two_resource)
{

	// Given
	rt_resource_s *resource_1 = rt_res_new_resource("/a/light");
	rt_resource_s *resource_2 = rt_res_new_resource("/b/airconditioner");

	// When
	rt_res_register_resource(resource_1);
	rt_res_register_resource(resource_2);

	// Then
	TEST_ASSERT_EQUAL(resource_1, rt_res_get_resource_by_href("/a/light"));
}

TEST(test_resources, rt_res_new_resource_duplicate_resource_return_null)
{
	// Given
	rt_resource_s *resource_1 = rt_res_new_resource("/a/light");
	rt_res_register_resource(resource_1);

	// When && Then
	TEST_ASSERT_EQUAL(NULL, rt_res_new_resource("/a/light"));
}

TEST(test_resources, rt_res_register_duplicate_resource_return_null)
{
	// Given
	rt_resource_s *resource_1 = rt_res_new_resource("/a/light");
	rt_resource_s *resource_2 = rt_res_new_resource("/a/light");

	// When
	rt_res_register_resource(resource_1);

	// Then
	TEST_ASSERT_EQUAL(OCF_RESOURCE_ERROR, rt_res_register_resource(resource_2));
	rt_mem_free(resource_2->href);
	rt_mem_free(resource_2);
}

TEST(test_resources, rt_res_get_resource_by_href_should_return_null_if_unregistered_href)
{
	// Given
	rt_res_register_resource(rt_res_new_resource("/a/light"));

	// When
	rt_resource_s *res = rt_res_get_resource_by_href("/invalid/href");

	// Then
	TEST_ASSERT_NULL(res);
}

static coap_packet_t recv_coap_packet[1];

static void get_handler_func(ocf_request_s request, ocf_rep_decoder_s data)
{
	pthread_mutex_lock(&g_mutex);
	rt_request_s *req = (rt_request_s *) request;
	recv_coap_packet->mid = req->data->mid;
	pthread_cond_signal(&g_condition);
	pthread_mutex_unlock(&g_mutex);
}

TEST(test_resources, rt_res_set_get_handler_func_return_ok)
{
	// Given
	coap_packet_t sent_coap_packet[1];
	uint16_t mid = rt_coap_get_mid();
	ocf_endpoint_s endpoint;
	const char *uri_path = "/a/light";
	uint8_t token[4];
	rt_random_rand_to_buffer(token, sizeof(token));
	resource = rt_res_new_resource(uri_path);
	rt_res_set_request_handler(resource, OCF_GET, get_handler_func);
	rt_res_register_resource(resource);

	rt_coap_init_message(sent_coap_packet, COAP_TYPE_NON, COAP_GET, mid);
	rt_coap_set_header_uri_path(sent_coap_packet, uri_path);
	rt_coap_set_token(sent_coap_packet, token, sizeof(token));

	rt_endpoint_set(&endpoint, "127.0.0.1", 5683, OCF_UDP | OCF_IPV4);

	// When
	uint8_t result[COAP_MAX_PACKET_SIZE + 1];
	uint16_t len = rt_coap_serialize_message(sent_coap_packet, result);
	rt_coap_receive(result, len, &endpoint);

	// Then
	int ret = wait_for_condition(&g_mutex, &g_condition);
	TEST_ASSERT_EQUAL_INT(0, ret);
	TEST_ASSERT_EQUAL_INT_MESSAGE(sent_coap_packet->mid, recv_coap_packet->mid, "Different mid came from receiving queue");
}

TEST(test_resources, rt_res_set_handler_null_func)
{
	// Givens
	resource = rt_res_new_resource("/a/light");
	rt_res_set_request_handler(resource, OCF_GET, NULL);
	rt_res_register_resource(resource);

	// When
	rt_resource_s *res = rt_res_get_resource_by_href("/a/light");

	// Then
	TEST_ASSERT_EQUAL(NULL, res->get_handler);
}

TEST(test_resources, rt_res_set_discoverable_with_false)
{
	// Given
	resource = rt_res_new_resource("/a/light");
	rt_res_register_resource(resource);
	// When
	rt_res_set_discoverable(resource, false);
	rt_res_set_discoverable(resource, true);
	rt_res_set_discoverable(resource, false);

	// Then
	TEST_ASSERT_FALSE_MESSAGE(rt_res_is_discoverable(resource), "rt_res_set_discoverable failed with false");
}

TEST(test_resources, rt_res_set_discoverable_with_true)
{
	// Given
	resource = rt_res_new_resource("/a/light");
	rt_res_register_resource(resource);
	// When
	rt_res_set_discoverable(resource, false);
	rt_res_set_discoverable(resource, true);

	// Then
	TEST_ASSERT_TRUE_MESSAGE(rt_res_is_discoverable(resource), "rt_res_set_discoverable failed with true");
}

TEST(test_resources, rt_res_is_discoverable_with_false_after_registration)
{
	// Given
	resource = rt_res_new_resource("/a/light");
	rt_res_set_discoverable(resource, false);
	rt_res_set_discoverable(resource, true);
	rt_res_set_discoverable(resource, false);

	// When
	rt_res_register_resource(resource);
	rt_resource_s *res = rt_res_get_resource_by_href("/a/light");

	// Then
	TEST_ASSERT_FALSE_MESSAGE(rt_res_is_discoverable(res), "rt_res_is_discoverable returns true with rt_res_get_resource_by_href");
}

TEST(test_resources, rt_res_is_discoverable_with_true_after_registration)
{
	// Given
	resource = rt_res_new_resource("/a/light");
	rt_res_set_discoverable(resource, false);
	rt_res_set_discoverable(resource, true);

	// When
	rt_res_register_resource(resource);
	rt_resource_s *res = rt_res_get_resource_by_href("/a/light");

	// Then
	TEST_ASSERT_TRUE_MESSAGE(rt_res_is_discoverable(res), "rt_res_is_discoverable returns false with rt_res_get_resource_by_href");
}

TEST(test_resources, rt_res_set_observable_with_false)
{
	// Given
	resource = rt_res_new_resource("/a/light");

	// When
	rt_res_set_observable(resource, false);
	rt_res_set_observable(resource, true);
	rt_res_set_observable(resource, false);
	rt_res_register_resource(resource);
	// Then
	TEST_ASSERT_FALSE_MESSAGE(rt_res_is_observable(resource), "rt_res_set_observable failed with false");
}

TEST(test_resources, rt_res_set_observable_with_true)
{
	// Given
	resource = rt_res_new_resource("/a/light");

	// When
	rt_res_set_observable(resource, false);
	rt_res_set_observable(resource, true);
	rt_res_register_resource(resource);
	// Then
	TEST_ASSERT_TRUE_MESSAGE(rt_res_is_observable(resource), "rt_res_set_observable failed with true");
}

TEST(test_resources, rt_res_is_observable_with_false_after_registration)
{
	// Given
	resource = rt_res_new_resource("/a/light");
	rt_res_set_observable(resource, false);
	rt_res_set_observable(resource, true);
	rt_res_set_observable(resource, false);

	// When
	rt_res_register_resource(resource);
	rt_resource_s *res = rt_res_get_resource_by_href("/a/light");

	// Then
	TEST_ASSERT_FALSE_MESSAGE(rt_res_is_observable(res), "rt_res_is_observable returns true with rt_res_get_resource_by_href");
}

TEST(test_resources, rt_res_is_observable_with_true_after_registration)
{
	// Given
	resource = rt_res_new_resource("/a/light");
	rt_res_set_observable(resource, false);
	rt_res_set_observable(resource, true);

	// When
	rt_res_register_resource(resource);
	rt_resource_s *res = rt_res_get_resource_by_href("/a/light");

	// Then
	TEST_ASSERT_TRUE_MESSAGE(rt_res_is_observable(res), "rt_res_is_observable returns false with rt_res_get_resource_by_href");
}

TEST(test_resources, rt_res_set_secure_with_false)
{
	// Given
	resource = rt_res_new_resource("/a/light");

	// When
	rt_res_set_secure(resource, false);
	rt_res_set_secure(resource, true);
	rt_res_set_secure(resource, false);
	rt_res_register_resource(resource);
	// Then
	TEST_ASSERT_FALSE_MESSAGE(rt_res_is_secure(resource), "rt_res_set_secure failed with false");
}

TEST(test_resources, rt_res_set_secure_with_true)
{
	// Given
	resource = rt_res_new_resource("/a/light");

	// When
	rt_res_set_secure(resource, false);
	rt_res_set_secure(resource, true);
	rt_res_register_resource(resource);
	// Then
	TEST_ASSERT_TRUE_MESSAGE(rt_res_is_secure(resource), "rt_res_set_secure failed with true");
}

TEST(test_resources, rt_res_is_secure_with_false_after_registration)
{
	// Given
	resource = rt_res_new_resource("/a/light");
	rt_res_set_secure(resource, false);
	rt_res_set_secure(resource, true);
	rt_res_set_secure(resource, false);

	// When
	rt_res_register_resource(resource);
	rt_resource_s *res = rt_res_get_resource_by_href("/a/light");

	// Then
	TEST_ASSERT_FALSE_MESSAGE(rt_res_is_secure(res), "rt_res_is_secure returns true with rt_res_get_resource_by_href");
}

TEST(test_resources, rt_res_is_secure_with_true_after_registration)
{
	// Given
	resource = rt_res_new_resource("/a/light");

	rt_res_set_secure(resource, false);
	rt_res_set_secure(resource, true);

	// When
	rt_res_register_resource(resource);
	rt_resource_s *res = rt_res_get_resource_by_href("/a/light");

	// Then
	TEST_ASSERT_TRUE_MESSAGE(rt_res_is_secure(res), "rt_res_is_secure returns false with rt_res_get_resource_by_href");
}

TEST(test_resources, rt_res_set_default_interface)
{
	// Given
	resource = rt_res_new_resource("/a/light");

	// When
	rt_res_set_default_interface(resource, OIC_IF_BASELINE);
	rt_res_register_resource(resource);
	// Then
	uint8_t interface = 0;
	rt_res_get_default_interface(resource, &interface);
	TEST_ASSERT_EQUAL_INT_MESSAGE(OIC_IF_BASELINE, interface, "baseline interface was not set with OIC_IF_BASELINE");
	TEST_ASSERT_EQUAL_INT16_MESSAGE(OCF_OK, rt_res_is_interface_supported(resource, OIC_IF_BASELINE), "OIC_IF_BASELINE wasn't set");
}

TEST(test_resources, rt_res_set_interface)
{
	// Given
	resource = rt_res_new_resource("/a/light");

	// When
	rt_res_set_interface(resource, OIC_IF_R);
	rt_res_set_interface(resource, OIC_IF_BASELINE);
	rt_res_register_resource(resource);
	// Then
	TEST_ASSERT_EQUAL_INT16_MESSAGE(OCF_OK, rt_res_is_interface_supported(resource, OIC_IF_R), "OIC_IF_R wasn't set");
	TEST_ASSERT_EQUAL_INT16_MESSAGE(OCF_OK, rt_res_is_interface_supported(resource, OIC_IF_BASELINE), "OIC_IF_BASELINE wasn't set");
}

TEST(test_resources, rt_res_set_resource_type)
{
	// Given
	resource = rt_res_new_resource("/oic/res");

	// When
	const char *str_types[2] = { "oic.wk.res", "oic.wk.d" };
	rt_res_set_resource_types(resource, str_types, 2);

	rt_res_register_resource(resource);
	// Then
	ocf_result_t result = rt_res_is_resource_type_supported(resource, "oic.wk.res");
	TEST_ASSERT_EQUAL_INT_MESSAGE(OCF_OK, result, "oic.wk.res wasn't set");
}

TEST(test_resources, rt_res_add_if_rt_rep)
{
	// Given

	rt_rep_encoder_s *rep = rt_rep_encoder_init(OCF_REP_MAP);
	resource = rt_res_new_resource("/oic/res");
	const char *str_types[2] = { "oic.wk.res", "oic.wk.p" };
	rt_res_set_resource_types(resource, str_types, 2);
	rt_res_register_resource(resource);
	// When
	ocf_result_t result = rt_res_add_if_rt_rep(rep, resource);
	if (result != OCF_OK) {
		goto exit;
	}

	rt_rep_decoder_s *decoded_rep = NULL, array;
	decoded_rep = rt_rep_decoder_init(rep->payload, rep->payload_size);
	result = rt_rep_get_array_from_map(decoded_rep, OIC_RT_NAME, &array);
	if (result != OCF_OK) {
		goto exit;
	}

	result = rt_rep_get_array_from_map(decoded_rep, OIC_IF_NAME, &array);
	if (result != OCF_OK) {
		goto exit;
	}

exit:
	rt_rep_encoder_release(rep);

	//then
	TEST_ASSERT_EQUAL_INT(OCF_OK, result);
}

TEST_GROUP_RUNNER(test_resources)
{
	RUN_TEST_CASE(test_resources, rt_res_register_resource_one_resource);
	RUN_TEST_CASE(test_resources, rt_res_register_resource_two_resource);
	RUN_TEST_CASE(test_resources, rt_res_get_resource_by_href_should_return_null_if_unregistered_href);
	RUN_TEST_CASE(test_resources, rt_res_set_get_handler_func_return_ok);
	RUN_TEST_CASE(test_resources, rt_res_set_handler_null_func);
	RUN_TEST_CASE(test_resources, rt_res_register_duplicate_resource_return_null);
	RUN_TEST_CASE(test_resources, rt_res_new_resource_duplicate_resource_return_null);
	RUN_TEST_CASE(test_resources, rt_res_set_discoverable_with_true);
	RUN_TEST_CASE(test_resources, rt_res_set_discoverable_with_false);
	RUN_TEST_CASE(test_resources, rt_res_is_discoverable_with_false_after_registration);
	RUN_TEST_CASE(test_resources, rt_res_is_discoverable_with_true_after_registration);
	RUN_TEST_CASE(test_resources, rt_res_set_observable_with_true);
	RUN_TEST_CASE(test_resources, rt_res_set_observable_with_false);
	RUN_TEST_CASE(test_resources, rt_res_is_observable_with_false_after_registration);
	RUN_TEST_CASE(test_resources, rt_res_is_observable_with_true_after_registration);
	RUN_TEST_CASE(test_resources, rt_res_set_secure_with_true);
	RUN_TEST_CASE(test_resources, rt_res_set_secure_with_false);
	RUN_TEST_CASE(test_resources, rt_res_is_secure_with_false_after_registration);
	RUN_TEST_CASE(test_resources, rt_res_is_secure_with_true_after_registration);
	RUN_TEST_CASE(test_resources, rt_res_set_default_interface);
	RUN_TEST_CASE(test_resources, rt_res_set_interface);
	RUN_TEST_CASE(test_resources, rt_res_set_resource_type);
	RUN_TEST_CASE(test_resources, rt_res_add_if_rt_rep);
}

#ifndef CONFIG_ENABLE_RT_OCF

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_resources);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
