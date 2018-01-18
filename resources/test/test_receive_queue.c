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
#include "rt_receive_queue.h"
#include "ocf_types.h"
#include "rt_coap.h"
#include "rt_mem.h"
#include "rt_logger.h"
#include "test_common.h"

#define TAG "TEST_RECV_QUEUE"

static pthread_cond_t g_condition;
static pthread_mutex_t g_mutex;

TEST_GROUP(test_receive_queue);

TEST_SETUP(test_receive_queue)
{
	rt_mem_pool_init();
	rt_receive_queue_init();
	pthread_mutex_init(&g_mutex, NULL);
	pthread_cond_init(&g_condition, NULL);
}

TEST_TEAR_DOWN(test_receive_queue)
{
	pthread_cond_destroy(&g_condition);
	pthread_mutex_destroy(&g_mutex);
	rt_receive_queue_terminate();
	rt_mem_pool_terminate();
}

TEST(test_receive_queue, init)
{
	// When
	rt_receive_queue_terminate();
	int ret = rt_receive_queue_init();

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
}

static void handler_callback(const rt_data_s *packet, const ocf_endpoint_s *endpont)
{
	usleep(10 * 1000);
	pthread_mutex_lock(&g_mutex);
	pthread_cond_signal(&g_condition);
	pthread_mutex_unlock(&g_mutex);
}

TEST(test_receive_queue, enqueue_success)
{
	// Given
	rt_receive_queue_set_request_callback(handler_callback);

	uint16_t mid = rt_coap_get_mid();
	coap_packet_t msg[1];
	rt_coap_init_message(msg, COAP_TYPE_CON, COAP_GET, mid);
	rt_coap_set_header_uri_path(msg, "/a/light");

	rt_token_s token;
	token.len = TOKEN_LEN;
	rt_random_rand_to_buffer(token.token, token.len);
	rt_coap_set_token(msg, token.token, token.len);
	rt_coap_set_header_uri_query(msg, "rt=core.light");
	rt_data_s *packet = rt_receive_data_make_item(msg);
	ocf_endpoint_s endpoint;

	// When
	int ret = rt_receive_queue_request_enqueue(packet, &endpoint);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
}

TEST(test_receive_queue, enqueue_fail)
{
	// Given
	rt_receive_queue_set_request_callback(handler_callback);

	// When
	int ret = rt_receive_queue_request_enqueue(NULL, NULL);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, ret);
}

TEST(test_receive_queue, enqueue_fail_when_not_initialized)
{
	// Given
	rt_receive_queue_terminate();
	
	uint16_t mid = rt_coap_get_mid();
	coap_packet_t msg[1];
	rt_coap_init_message(msg, COAP_TYPE_CON, COAP_GET, mid);
	rt_coap_set_header_uri_path(msg, "/a/light");

	rt_token_s token;

	token.len = TOKEN_LEN;
	rt_random_rand_to_buffer(token.token, token.len);
	rt_coap_set_token(msg, token.token, token.len);
	
	rt_coap_set_header_uri_query(msg, "rt=core.light");
	rt_data_s *packet = rt_receive_data_make_item(msg);
	ocf_endpoint_s endpoint;

	// When
	int ret = rt_receive_queue_request_enqueue(packet, &endpoint);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_NOT_INITIALIZE, ret);
	rt_data_free_item(packet);
}

TEST(test_receive_queue, dequeue_handler)
{
	// Given
	rt_receive_queue_set_request_callback(handler_callback);

	uint16_t mid = rt_coap_get_mid();
	coap_packet_t msg[1];
	rt_coap_init_message(msg, COAP_TYPE_CON, COAP_GET, mid);
	rt_coap_set_header_uri_path(msg, "/a/light");

	rt_token_s token;
	token.len = TOKEN_LEN;
	rt_random_rand_to_buffer(token.token, token.len);
	rt_coap_set_token(msg, token.token, token.len);
	
	rt_coap_set_header_uri_query(msg, "rt=core.light");
	rt_data_s *packet = rt_receive_data_make_item(msg);
	ocf_endpoint_s endpoint;

	// When
	// Handler가 불리고 정상적으로 처리된다.
	rt_receive_queue_request_enqueue(packet, &endpoint);

	// Then
	TEST_ASSERT_EQUAL(0, wait_for_condition(&g_mutex, &g_condition));
}

TEST_GROUP_RUNNER(test_receive_queue)
{
	RUN_TEST_CASE(test_receive_queue, init);
	RUN_TEST_CASE(test_receive_queue, enqueue_success);
	RUN_TEST_CASE(test_receive_queue, enqueue_fail);
	RUN_TEST_CASE(test_receive_queue, enqueue_fail_when_not_initialized);
	RUN_TEST_CASE(test_receive_queue, dequeue_handler);
}

#ifndef CONFIG_IOTIVITY_RT

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_receive_queue);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
