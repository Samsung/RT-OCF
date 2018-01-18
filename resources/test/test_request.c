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
#include "rt_request.h"
#include "rt_rep.h"
#include "rt_resources.h"
#include "rt_endpoint.h"
#include "rt_logger.h"
#include "test_common.h"

#include <sys/time.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <string.h>

#define TAG "TEST_REQ"

#define BUFFERSIZE 1024

static pthread_cond_t g_condition;
static pthread_mutex_t g_mutex;

static uint16_t get_normal_socket_port(void);

#define RES_LIGHT "/a/light"
#define RES_POWER "/a/power"
#define INTERFACE_VALUE_COMPARISION (OIC_IF_BASELINE | OIC_IF_A)

static ocf_persistent_storage_handler_s temp_doxm_handler = { test_doxm_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_cred_handler = { test_cred_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_acl2_handler = { test_acl2_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_pstat_handler = { test_pstat_fopen, fread, fwrite, fclose };

TEST_GROUP(test_request);

TEST_SETUP(test_request)
{
	create_security_data_files();
	ocf_sec_register_ps_handler(&temp_doxm_handler, &temp_pstat_handler, &temp_cred_handler, &temp_acl2_handler);
	ocf_init(OCF_CLIENT_SERVER, "Samsung", OCF_SH_100);
	pthread_mutex_init(&g_mutex, NULL);
	pthread_cond_init(&g_condition, NULL);
}

TEST_TEAR_DOWN(test_request)
{
	pthread_cond_destroy(&g_condition);
	pthread_mutex_destroy(&g_mutex);
	ocf_terminate();
	remove_security_data_files();
}

TEST(test_request, get_send_without_callback)
{
	// Given
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 8888, OCF_UDP | OCF_IPV4);	// TODO: Should add OCF_SECURE;

	// When
	ocf_result_t ret = rt_request_get_send(&endpoint, ".well-known/core", NULL, true, NULL);

	// Then
	TEST_ASSERT_EQUAL_INT(ret, OCF_INVALID_PARAM);
}

static void get_callback(ocf_rep_decoder_s rep, ocf_response_result_t code)
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

TEST(test_request, get_send_with_callback)
{
	// Given
	const char *uri_path = RES_LIGHT;
	rt_resource_s *resource = rt_res_new_resource(uri_path);
	rt_res_set_request_handler(resource, OCF_GET, get_handler_func);
	rt_res_register_resource(resource);

	uint16_t port = get_normal_socket_port();
	RT_LOG_D(TAG, "Socket & Port : %d : %d", socket, port);

	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", port, OCF_UDP | OCF_IPV4);	// TODO: Should add OCF_SECURE;

	// When
	ocf_result_t ret = rt_request_get_send(&endpoint, uri_path, NULL, true, get_callback);

	// Then
	TEST_ASSERT_EQUAL_INT(ret, OCF_OK);
	TEST_ASSERT_EQUAL_INT(0, wait_for_condition(&g_mutex, &g_condition));
}

static void get_unsupport_if_callback(ocf_rep_decoder_s rep, ocf_response_result_t code)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	pthread_mutex_lock(&g_mutex);
	pthread_cond_signal(&g_condition);
	pthread_mutex_unlock(&g_mutex);
	TEST_ASSERT_EQUAL_INT(OCF_RESPONSE_BAD_REQ, code);
	RT_LOG_D(TAG, "OUT : %s", __func__);
}

TEST(test_request, get_send_with_unsupported_if_query)
{
	// Given
	const char *uri_path = RES_LIGHT;
	rt_resource_s *resource = rt_res_new_resource(uri_path);
	rt_res_set_request_handler(resource, OCF_GET, get_handler_func);
	rt_res_set_interface(resource, OIC_IF_S);
	rt_res_register_resource(resource);

	int socket;
	rt_udp_get_normal_sock_v4(&socket);

	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	if (-1 == getsockname(socket, (struct sockaddr *)&addr, &len)) {
		RT_LOG_E(TAG, "getsockname failaed");
	}

	uint16_t port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
	RT_LOG_D(TAG, "Socket & Port : %d : %d", socket, port);

	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", port, OCF_UDP | OCF_IPV4);

	char interface_query[30] = { 0, };
	const char *if_print = "if=%s";
	char interface_str[20] = { 0, };
	rt_res_get_interface_string_value(OIC_IF_A, interface_str);
	sprintf(interface_query, if_print, interface_str);

	// When
	ocf_result_t ret = rt_request_get_send(&endpoint, uri_path, interface_query, true, get_unsupport_if_callback);

	// Then
	TEST_ASSERT_EQUAL_INT(ret, OCF_OK);
	TEST_ASSERT_EQUAL_INT(0, wait_for_condition(&g_mutex, &g_condition));
}

TEST(test_request, discovery_without_callback)
{
	// Given

	// When
	ocf_result_t ret = rt_discovery(NULL, NULL);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, ret);
}

static void discover_callback(ocf_remote_resource_s *remote_resources, ocf_response_result_t eh_result)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	TEST_ASSERT_NOT_NULL(remote_resources);

	ocf_remote_resource_s *cur_resource = remote_resources;
	while (cur_resource) {
		RT_LOG_D(TAG, "RESOURCE HREF : %s", cur_resource->href);
		if (0 == strncmp(RES_LIGHT, cur_resource->href, strlen(cur_resource->href))) {
			TEST_ASSERT_EQUAL_STRING(RES_LIGHT, cur_resource->href);
			rt_resource_type_list_s *resource_type_list = cur_resource->resource_types;
			TEST_ASSERT_NOT_NULL(resource_type_list);

			while (resource_type_list) {
				if (0 == strncmp("oic.r.switch.binary", resource_type_list->resource_type, strlen(resource_type_list->resource_type))) {
					break;
				}
				resource_type_list = resource_type_list->next;
			}

			if (resource_type_list) {
				TEST_ASSERT_EQUAL_STRING("oic.r.switch.binary", resource_type_list->resource_type);
				TEST_ASSERT_EQUAL_UINT(INTERFACE_VALUE_COMPARISION, (cur_resource->interfaces) & INTERFACE_VALUE_COMPARISION);
				TEST_ASSERT_EQUAL_UINT(RT_OBSERVABLE | RT_DISCOVERABLE, cur_resource->p);

				ocf_endpoint_list_s *endpoint_list = cur_resource->endpoint_list;
				TEST_ASSERT_NOT_NULL(endpoint_list);
				TEST_ASSERT_NOT_EQUAL(0, endpoint_list->endpoint.port);
				TEST_ASSERT_NOT_EQUAL(0, endpoint_list->endpoint.addr[0]);

				TEST_ASSERT_NOT_NULL(endpoint_list->next);
				TEST_ASSERT_NOT_EQUAL(0, endpoint_list->next->endpoint.port);
				TEST_ASSERT_NOT_EQUAL(0, endpoint_list->next->endpoint.addr[0]);

				pthread_mutex_lock(&g_mutex);
				pthread_cond_signal(&g_condition);
				pthread_mutex_unlock(&g_mutex);
				break;
			}
		}
		cur_resource = cur_resource->next;
	}

	RT_LOG_D(TAG, "OUT : %s", __func__);
}

TEST(test_request, discovery_uri_with_callback)
{
	// Given
	const char *uri_path = RES_LIGHT;

	rt_resource_s *resource = rt_res_new_resource(uri_path);
	rt_res_set_request_handler(resource, OCF_GET, get_handler_func);
	const char *resource_types[1] = { "oic.r.switch.binary" };
	rt_res_set_resource_types(resource, resource_types, 1);
	rt_res_set_interface(resource, INTERFACE_VALUE_COMPARISION);
	rt_res_set_discoverable(resource, true);
	rt_res_set_observable(resource, true);
	rt_res_set_resource_protocol(resource, OCF_COAPS | OCF_COAP_TCP);

	rt_res_register_resource(resource);

	// When
	ocf_result_t ret = rt_discovery(discover_callback, NULL);

	// Then
	TEST_ASSERT_EQUAL_INT(ret, OCF_OK);
	TEST_ASSERT_EQUAL_INT(0, wait_for_condition(&g_mutex, &g_condition));
}

static void discover_with_rt_callback(ocf_remote_resource_s *remote_resources, ocf_response_result_t code)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	pthread_mutex_lock(&g_mutex);
	TEST_ASSERT_NOT_NULL(remote_resources);

	ocf_remote_resource_s *itr = remote_resources;
	int count_array[2] = { 0, 0 }, expected_array[2] = {
		1, 0
	};

	while (itr) {
		if (0 == strncmp(RES_LIGHT, remote_resources->href, strlen(RES_LIGHT))) {
			count_array[0]++;
		} else if (0 == strncmp(RES_POWER, remote_resources->href, strlen(RES_POWER))) {
			count_array[1]++;
		}
		itr = itr->next;
	}

	TEST_ASSERT_EQUAL_INT8_ARRAY(expected_array, count_array, 2);

	pthread_cond_signal(&g_condition);
	RT_LOG_D(TAG, "OUT : %s", __func__);
	pthread_mutex_unlock(&g_mutex);
}

TEST(test_request, discovery_with_rt_query)
{
	// Given
	const char *uri_path = RES_LIGHT;
	rt_resource_s *resource = rt_res_new_resource(uri_path);
	rt_res_set_request_handler(resource, OCF_GET, get_handler_func);
	const char *rts_light[1] = { "oic.r.light" };
	rt_res_set_resource_types(resource, rts_light, 1);
	rt_res_register_resource(resource);
	rt_res_set_discoverable(resource, true);
	rt_res_set_observable(resource, true);

	uri_path = RES_POWER;
	resource = rt_res_new_resource(uri_path);
	rt_res_set_request_handler(resource, OCF_GET, get_handler_func);
	const char *rts_power[1] = { "oic.r.power" };
	rt_res_set_resource_types(resource, rts_power, 1);
	rt_res_register_resource(resource);

	// When
	ocf_result_t ret = rt_discovery(discover_with_rt_callback, "rt=oic.r.light");

	// Then
	TEST_ASSERT_EQUAL_INT(ret, OCF_OK);
	TEST_ASSERT_EQUAL_INT(0, wait_for_condition(&g_mutex, &g_condition));
	RT_LOG_D(TAG, "OUT : %s", __func__);
}

TEST_GROUP_RUNNER(test_request)
{
	RUN_TEST_CASE(test_request, get_send_without_callback);
	RUN_TEST_CASE(test_request, get_send_with_callback);
	RUN_TEST_CASE(test_request, get_send_with_unsupported_if_query);
	RUN_TEST_CASE(test_request, discovery_without_callback);
	RUN_TEST_CASE(test_request, discovery_uri_with_callback);
	RUN_TEST_CASE(test_request, discovery_with_rt_query);
}

#ifndef CONFIG_IOTIVITY_RT

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_request);
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
