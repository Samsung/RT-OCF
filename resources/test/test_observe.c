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
#include "rt_manager.h"
#include "rt_observe.h"
#include "rt_rep.h"
#include "rt_resources.h"
#include "rt_endpoint.h"
#include "rt_logger.h"
#include "test_common.h"

#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#define TAG "TEST_OBSERVE"

#define BUFFERSIZE 1024

static pthread_cond_t g_condition;
static pthread_mutex_t g_mutex;

static uint16_t get_normal_socket_port(void);

#define RES_LIGHT "/a/light"
#define RES_POWER "/a/power"

static ocf_persistent_storage_handler_s temp_doxm_handler = { test_doxm_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_cred_handler = { test_cred_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_acl2_handler = { test_acl2_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_pstat_handler = { test_pstat_fopen, fread, fwrite, fclose };

TEST_GROUP(test_observe);

TEST_SETUP(test_observe)
{
	create_security_data_files();
	ocf_sec_register_ps_handler(&temp_doxm_handler, &temp_pstat_handler, &temp_cred_handler, &temp_acl2_handler);
	ocf_init(OCF_CLIENT_SERVER, "Samsung", OCF_SH_100);
	pthread_mutex_init(&g_mutex, NULL);
	pthread_cond_init(&g_condition, NULL);
}

TEST_TEAR_DOWN(test_observe)
{
	pthread_cond_destroy(&g_condition);
	pthread_mutex_destroy(&g_mutex);
	ocf_terminate();
	remove_security_data_files();
}

TEST(test_observe, observe_resource_without_callback)
{
	// Given
	const char *uri_path = RES_LIGHT;
	rt_resource_s *resource = rt_res_new_resource(uri_path);
	rt_res_register_resource(resource);
	rt_res_set_discoverable(resource, true);
	rt_res_set_observable(resource, true);

	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 8888, OCF_UDP | OCF_IPV4);

	// When
	ocf_result_t ret = rt_observe_register(&endpoint, uri_path, NULL);

	// Then
	TEST_ASSERT_EQUAL_INT(ret, OCF_INVALID_PARAM);
}

static void light_observe_callback(ocf_rep_decoder_s rep, ocf_response_result_t code)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	pthread_mutex_lock(&g_mutex);
	pthread_cond_signal(&g_condition);
	pthread_mutex_unlock(&g_mutex);
	RT_LOG_D(TAG, "OUT : %s", __func__);
}

static void get_handler_func(ocf_request_s request, ocf_rep_decoder_s data)
{
	RT_LOG_D(TAG, "IN : %s", __func__);

	rt_rep_encoder_s *rep_encoder = rt_rep_encoder_init(OCF_REP_MAP);
	rt_rep_add_bool_to_map(rep_encoder, "status", true);
	rt_rep_add_int_to_map(rep_encoder, "power", 110);

	rt_response_send((rt_request_s *) request, rep_encoder, OCF_RESPONSE_CONTENT);
	rt_rep_encoder_release(rep_encoder);

	RT_LOG_D(TAG, "OUT : %s", __func__);
}

TEST(test_observe, observe_resource_with_callback)
{
	// Given
	const char *uri_path = RES_LIGHT;
	rt_resource_s *resource = rt_res_new_resource(uri_path);
	rt_res_register_resource(resource);
	rt_res_set_request_handler(resource, OCF_GET, &get_handler_func);
	rt_res_set_discoverable(resource, true);
	rt_res_set_observable(resource, true);

	uint16_t port = get_normal_socket_port();
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", port, OCF_UDP | OCF_IPV4);
	TEST_ASSERT_NULL(resource->observe_list);

	// When
	ocf_result_t ret = rt_observe_register(&endpoint, uri_path, light_observe_callback);

	// Then
	TEST_ASSERT_EQUAL_INT(ret, OCF_OK);
	TEST_ASSERT_EQUAL_INT(0, wait_for_condition(&g_mutex, &g_condition));
	TEST_ASSERT_NOT_NULL(resource->observe_list);
}

TEST(test_observe, observe_the_same_resource_twice)
{
	// Given
	const char *uri_path = RES_LIGHT;
	rt_resource_s *resource = rt_res_new_resource(uri_path);
	rt_res_register_resource(resource);
	rt_res_set_request_handler(resource, OCF_GET, &get_handler_func);
	rt_res_set_discoverable(resource, true);
	rt_res_set_observable(resource, true);

	uint16_t port = get_normal_socket_port();
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", port, OCF_UDP | OCF_IPV4);

	// When
	rt_observe_register(&endpoint, uri_path, light_observe_callback);
	wait_for_condition(&g_mutex, &g_condition);
	rt_observe_register(&endpoint, uri_path, light_observe_callback);
	wait_for_condition(&g_mutex, &g_condition);

	// Then
	TEST_ASSERT_NOT_NULL(resource->observe_list);
	TEST_ASSERT_NULL(resource->observe_list->next);
}

TEST(test_observe, given_observed_resource_when_notify_then_callback_is_called)
{
	// Given
	const char *uri_path = RES_LIGHT;
	rt_resource_s *resource = rt_res_new_resource(uri_path);
	rt_res_register_resource(resource);
	rt_res_set_request_handler(resource, OCF_GET, &get_handler_func);
	rt_res_set_discoverable(resource, true);
	rt_res_set_observable(resource, true);

	uint16_t port = get_normal_socket_port();
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", port, OCF_UDP | OCF_IPV4);

	rt_observe_register(&endpoint, uri_path, light_observe_callback);
	wait_for_condition(&g_mutex, &g_condition);

	// When
	rt_rep_encoder_s *rep = rt_rep_encoder_init(OCF_REP_MAP);
	rt_rep_add_int_to_map(rep, "power", 100);

	ocf_result_t ret = rt_observe_notify(uri_path, rep);
	rt_rep_encoder_release(rep);

	// Then
	TEST_ASSERT_EQUAL_INT(ret, OCF_OK);
	TEST_ASSERT_EQUAL_INT(0, wait_for_condition(&g_mutex, &g_condition));
}

TEST(test_observe, given_observed_resource_when_cancel_observe_then_observe_list_should_be_empty)
{
	// Given
	const char *uri_path = RES_LIGHT;
	rt_resource_s *resource = rt_res_new_resource(uri_path);
	rt_res_register_resource(resource);
	rt_res_set_request_handler(resource, OCF_GET, &get_handler_func);
	rt_res_set_discoverable(resource, true);
	rt_res_set_observable(resource, true);

	uint16_t port = get_normal_socket_port();
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", port, OCF_UDP | OCF_IPV4);

	rt_observe_register(&endpoint, uri_path, light_observe_callback);
	wait_for_condition(&g_mutex, &g_condition);

	// When
	rt_observe_deregister(&endpoint, uri_path);
	sleep(1);

	// Then
	TEST_ASSERT_NULL(resource->observe_list);
}

TEST(test_observe, given_cancel_observed_resource_when_notify_then_callback_should_not_be_called)
{
	// Given
	const char *uri_path = RES_LIGHT;
	rt_resource_s *resource = rt_res_new_resource(uri_path);
	rt_res_register_resource(resource);
	rt_res_set_request_handler(resource, OCF_GET, &get_handler_func);
	rt_res_set_discoverable(resource, true);
	rt_res_set_observable(resource, true);

	uint16_t port = get_normal_socket_port();
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", port, OCF_UDP | OCF_IPV4);

	rt_observe_register(&endpoint, uri_path, light_observe_callback);
	wait_for_condition(&g_mutex, &g_condition);

	// When
	rt_observe_deregister(&endpoint, uri_path);
	sleep(2);

	rt_rep_encoder_s *rep = rt_rep_encoder_init(OCF_REP_MAP);
	rt_rep_add_int_to_map(rep, "power", 100);

	ocf_result_t ret = rt_observe_notify(uri_path, rep);
	rt_rep_encoder_release(rep);

	// Then
	TEST_ASSERT_EQUAL_INT(ret, OCF_OK);
	TEST_ASSERT_EQUAL_INT(110, wait_for_condition(&g_mutex, &g_condition));
}

TEST(test_observe, given_observed_resource_when_irrelevant_cancel_observe_then_observe_should_not_be_deleted)
{
	// Given
	const char *uri_path = RES_LIGHT;
	rt_resource_s *resource = rt_res_new_resource(uri_path);
	rt_res_register_resource(resource);
	rt_res_set_request_handler(resource, OCF_GET, &get_handler_func);
	rt_res_set_discoverable(resource, true);
	rt_res_set_observable(resource, true);

	uint16_t port = get_normal_socket_port();
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", port, OCF_UDP | OCF_IPV4);

	rt_observe_register(&endpoint, uri_path, light_observe_callback);
	wait_for_condition(&g_mutex, &g_condition);

	// When
	rt_observe_deregister(&endpoint, "mylight");

	rt_rep_encoder_s *rep = rt_rep_encoder_init(OCF_REP_MAP);
	rt_rep_add_int_to_map(rep, "power", 100);

	ocf_result_t ret = rt_observe_notify(uri_path, rep);
	rt_rep_encoder_release(rep);

	// Then
	TEST_ASSERT_EQUAL_INT(ret, OCF_OK);
	TEST_ASSERT_EQUAL_INT(0, wait_for_condition(&g_mutex, &g_condition));
}

TEST_GROUP_RUNNER(test_observe)
{
	RUN_TEST_CASE(test_observe, observe_resource_without_callback);
	RUN_TEST_CASE(test_observe, observe_resource_with_callback);
	RUN_TEST_CASE(test_observe, observe_the_same_resource_twice);
	RUN_TEST_CASE(test_observe, given_observed_resource_when_notify_then_callback_is_called);
	RUN_TEST_CASE(test_observe, given_observed_resource_when_cancel_observe_then_observe_list_should_be_empty);
	RUN_TEST_CASE(test_observe, given_cancel_observed_resource_when_notify_then_callback_should_not_be_called);
	RUN_TEST_CASE(test_observe, given_observed_resource_when_irrelevant_cancel_observe_then_observe_should_not_be_deleted);
}

#ifndef CONFIG_ENABLE_RT_OCF

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_observe);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif

static uint16_t get_normal_socket_port(void)
{
	int socket;
	rt_udp_get_normal_sock_v4(&socket);

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	if (-1 == getsockname(socket, (struct sockaddr *)&addr, &len)) {
		RT_LOG_E(TAG, "getsockname failaed");
	}
	uint16_t port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
	return port;
}
