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

#include "rt_request.h"
#include "rt_resources.h"
#include "rt_rep.h"
#include "rt_coap.h"
#include "rt_coap_block.h"
#include "rt_mem.h"

#include "rt_logger.h"
#include "test_common.h"

#define TAG "TC_COAP_BLK"

// #define WAIT_TIME_SECONDS 10
#define POWER_KEY "power"
#define POWER_VALUE 10
#define STR_KEY "str"

static pthread_cond_t g_condition;
static pthread_mutex_t g_mutex;

static const char *LIGHT_URI = "/a/light";
static const char *ref_str =
	"Please don't see just a boy caught up in dreams and fantasies Please see me reaching out for someone I can't see Take my hand let's see where we wake up tomorrow Best laid plans sometimes are just a one night stand I'd be damned Cupid's demanding back his arrow So let's get drunk on our tears and God, tell us the reason youth is wasted on the young It's hunting season and the lambs are on the run Searching for meaning But are we all lost stars, trying to light up the dark? Who are we? Just a speck of dust within the galaxy? Woe is me, if we're not careful turns into reality Don't you dare let our best memories bring you sorrow Yesterday I saw a lion kiss a deer Turn the page maybe we'll find a brand new ending Where we're dancing in our tears and God, tell us the reason youth is wasted on the young It's hunting season and the lambs are on the run Searching for meaning But are we all lost stars, trying to light up the dark? I thought I saw you out there crying I thought I heard you call my name I thought I heard you out there crying Just the same God, give us the reason youth is wasted on the young It's hunting season and this lamb is on the run Searching for meaning But are we all lost stars, trying to light up the dark? I thought I saw you out there crying I thought I heard you call my name I thought I heard you out there crying But are we all lost stars, trying to light up the dark? But are we all lost stars, trying to light up the dark?Please don't see just a boy caught up in dreams and fantasies Please see me reaching out for someone I can't see Take my hand let's see where we wake up tomorrow Best laid plans sometimes are just a one night stand I'd be damned Cupid's demanding back his arrow So let's get drunk on our tears and God, tell us the reason youth is wasted on the young It's hunting season and the lambs are on the run Searching for meaning But are we all lost stars, trying to light up the dark? Who are we? Just a speck of dust within the galaxy? Woe is me, if we're not careful turns into reality Don't you dare let our best memories bring you sorrow Yesterday I saw a lion kiss a deer Turn the page maybe we'll find a brand new ending Where we're dancing in our tears and God, tell us the reason youth is wasted on the young It's hunting season and the lambs are on the run Searching for meaning But are we all lost stars, trying to light up the dark? I thought I saw you out there crying I thought I heard you call my name I thought I heard you out there crying Just the same God, give us the reason youth is wasted on the young It's hunting season and this lamb is on the run Searching for meaning But are we all lost stars, trying to light up the dark? I thought I saw you out there crying I thought I heard you call my name I thought I heard you out there crying But are we all lost stars, trying to light up the dark? But are we all lost stars, trying to light up the dark?Please don't see just a boy caught up in dreams and fantasies Please see me reaching out for someone I can't see Take my hand let's see where we wake up tomorrow Best laid plans sometimes are just a one night stand I'd be damned Cupid's demanding back his arrow So let's get drunk on our tears and God, tell us the reason youth is wasted on the young It's hunting season and the lambs are on the run Searching for meaning But are we all lost stars, trying to light up the dark? Who are we? Just a speck of dust within the galaxy? Woe is me, if we're not careful turns into reality Don't you dare let our best memories bring you sorrow Yesterday I saw a lion kiss a deer Turn the page maybe we'll find a brand new ending Where we're dancing in our tears and God, tell us the reason youth is wasted on the young It's hunting season and the lambs are on the run Searching for meaning But are we all lost stars, trying to light up the dark? I thought I saw you out there crying I thought I heard you call my name I thought I heard you out there crying Just the same God, give us the reason youth is wasted on the young It's hunting season and this lamb is on the run Searching for meaning But are we all lost stars, trying to light up the dark? I thought I saw you out there crying I thought I heard you call my name I thought I heard you out there crying But are we all lost stars, trying to light up the dark? But are we all lost stars, trying to light up the dark?";

static ocf_persistent_storage_handler_s temp_doxm_handler = { test_doxm_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_cred_handler = { test_cred_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_acl2_handler = { test_acl2_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_pstat_handler = { test_pstat_fopen, fread, fwrite, fclose };

TEST_GROUP(test_coap_block);

TEST_SETUP(test_coap_block)
{
	pthread_mutex_init(&g_mutex, NULL);
	pthread_cond_init(&g_condition, NULL);
	create_security_data_files();
	ocf_sec_register_ps_handler(&temp_doxm_handler, &temp_pstat_handler, &temp_cred_handler, &temp_acl2_handler);
	ocf_init(OCF_CLIENT_SERVER, "Samsung", "1.0");
}

TEST_TEAR_DOWN(test_coap_block)
{
	ocf_terminate();
	remove_security_data_files();
	pthread_cond_destroy(&g_condition);
	pthread_mutex_destroy(&g_mutex);
}

TEST(test_coap_block, rt_coap_block_init)
{
}

TEST(test_coap_block, rt_coap_block_is_block_need_success)
{
	//Given
	rt_rep_encoder_s *rep = rt_rep_encoder_init(OCF_REP_MAP);
	rt_rep_add_int_to_map(rep, POWER_KEY, POWER_VALUE);
	rt_rep_add_string_to_map(rep, STR_KEY, ref_str);

	rt_data_s data = {
		.flags = RT_OPTION_TRANSACTION_REQUEST,
		.payload = rep ? rep->payload : NULL,
		.payload_len = rep ? rep->payload_size : 0
	};

	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 40989, OCF_UDP | OCF_IPV4);

	//When
	bool ret = rt_coap_block_is_block_need(&data, &endpoint);

	//Then
	TEST_ASSERT_TRUE(ret);
	rt_rep_encoder_release(rep);
}

TEST(test_coap_block, rt_coap_block_is_block_need_fail_with_small_size)
{
	//Given
	rt_rep_encoder_s *rep = rt_rep_encoder_init(OCF_REP_MAP);
	rt_rep_add_int_to_map(rep, POWER_KEY, POWER_VALUE);

	rt_data_s data = {
		.flags = RT_OPTION_TRANSACTION_REQUEST,
		.payload = rep ? rep->payload : NULL,
		.payload_len = rep ? rep->payload_size : 0
	};

	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 40989, OCF_UDP | OCF_IPV4);

	//When
	bool ret = rt_coap_block_is_block_need(&data, &endpoint);

	//Then
	TEST_ASSERT_FALSE(ret);
	rt_rep_encoder_release(rep);
}

TEST(test_coap_block, rt_coap_block_is_block_need_fail_with_tcp_endpoint)
{
	//Given
	rt_rep_encoder_s *rep = rt_rep_encoder_init(OCF_REP_MAP);
	rt_rep_add_int_to_map(rep, POWER_KEY, POWER_VALUE);
	rt_rep_add_string_to_map(rep, STR_KEY, ref_str);

	rt_data_s data = {
		.flags = RT_OPTION_TRANSACTION_REQUEST,
		.payload = rep ? rep->payload : NULL,
		.payload_len = rep ? rep->payload_size : 0
	};

	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 40989, OCF_TCP | OCF_IPV4);

	//When
	bool ret = rt_coap_block_is_block_need(&data, &endpoint);

	//Then
	TEST_ASSERT_FALSE(ret);
	rt_rep_encoder_release(rep);
}

static void light_post_callback(ocf_rep_decoder_s rep, ocf_response_result_t code)
{
	pthread_mutex_lock(&g_mutex);
	pthread_cond_signal(&g_condition);
	pthread_mutex_unlock(&g_mutex);

	TEST_ASSERT_EQUAL_INT(OCF_RESPONSE_CONTENT, code);

	int power;
	rt_rep_get_int_from_map((rt_rep_decoder_s *) rep, POWER_KEY, &power);
	TEST_ASSERT_EQUAL_INT(POWER_VALUE, power);
	size_t str_len;
	ocf_result_t ret = rt_rep_get_string_length_from_map((rt_rep_decoder_s *) rep, STR_KEY, &str_len);
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_UINT32(strlen(ref_str), str_len);
	char *str = (char *)rt_mem_alloc(sizeof(char) * (str_len + 1));
	rt_rep_get_string_from_map((rt_rep_decoder_s *) rep, STR_KEY, str);
	TEST_ASSERT_EQUAL_STRING_LEN(ref_str, str, str_len);
	rt_mem_free(str);
}

static void post_handler_func(ocf_request_s request, ocf_rep_decoder_s rep)
{
	RT_LOG_D(TAG, "IN : %s", __func__);

	pthread_mutex_lock(&g_mutex);
	pthread_cond_signal(&g_condition);
	pthread_mutex_unlock(&g_mutex);

	int power;
	rt_rep_get_int_from_map((rt_rep_decoder_s *) rep, POWER_KEY, &power);
	TEST_ASSERT_EQUAL_INT(POWER_VALUE, power);
	size_t str_len;
	ocf_result_t ret = rt_rep_get_string_length_from_map((rt_rep_decoder_s *) rep, STR_KEY, &str_len);
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_UINT32(strlen(ref_str), str_len);
	char *str = (char *)rt_mem_alloc(sizeof(char) * (str_len + 1));
	rt_rep_get_string_from_map((rt_rep_decoder_s *) rep, STR_KEY, str);
	TEST_ASSERT_EQUAL_STRING_LEN(ref_str, str, str_len);
	rt_mem_free(str);
	// ocf_result_t ret = rt_response_send(request, g_response_data, strlen(g_response_data), OCF_RESPONSE_CONTENT);
	// RT_LOG_D(TAG, "Send ACK[%d] : %s", ret, g_response_data);
	// RT_LOG_D(TAG, "OUT : %s", __func__);
}

static void post_request(bool is_ack)
{
	//Given
	const char *uri_path = LIGHT_URI;
	rt_resource_s *resource = rt_res_new_resource(uri_path);
	rt_res_set_request_handler(resource, OCF_POST, post_handler_func);
	rt_res_register_resource(resource);

	uint16_t udp_normal_port_v4 = 0;
	rt_get_ports_v4(&udp_normal_port_v4, NULL, NULL, NULL);

	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", udp_normal_port_v4, OCF_UDP | OCF_IPV4);

	//When
	rt_rep_encoder_s *rep = rt_rep_encoder_init(OCF_REP_MAP);
	rt_rep_add_int_to_map(rep, POWER_KEY, POWER_VALUE);
	rt_rep_add_string_to_map(rep, STR_KEY, ref_str);

	ocf_result_t ret = rt_request_post_send(&endpoint, uri_path, NULL, rep, is_ack, light_post_callback);
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	rt_rep_encoder_release(rep);

	//Then
	TEST_ASSERT_EQUAL_INT(0, wait_for_condition(&g_mutex, &g_condition));
}

TEST(test_coap_block, rt_coap_block1_send_NON_packet)
{
	post_request(false);
}

TEST(test_coap_block, rt_coap_block1_send_CON_packet)
{
	post_request(true);
}

static void light_get_callback(ocf_rep_decoder_s rep, ocf_response_result_t code)
{
	pthread_mutex_lock(&g_mutex);
	pthread_cond_signal(&g_condition);
	pthread_mutex_unlock(&g_mutex);

	TEST_ASSERT_EQUAL_INT(OCF_RESPONSE_CONTENT, code);

	int power;
	rt_rep_get_int_from_map((rt_rep_decoder_s *) rep, POWER_KEY, &power);
	TEST_ASSERT_EQUAL_INT(POWER_VALUE, power);
	size_t str_len;
	ocf_result_t ret = rt_rep_get_string_length_from_map((rt_rep_decoder_s *) rep, STR_KEY, &str_len);
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_UINT32(strlen(ref_str), str_len);
	char *str = (char *)rt_mem_alloc(sizeof(char) * (str_len + 1));
	rt_rep_get_string_from_map((rt_rep_decoder_s *) rep, STR_KEY, str);
	TEST_ASSERT_EQUAL_STRING_LEN(ref_str, str, str_len);
	rt_mem_free(str);
}

static void get_handler_func(ocf_request_s request, ocf_rep_decoder_s data)
{
	RT_LOG_D(TAG, "IN : %s", __func__);

	rt_rep_encoder_s *rep = rt_rep_encoder_init(OCF_REP_MAP);
	rt_rep_add_int_to_map(rep, POWER_KEY, POWER_VALUE);
	rt_rep_add_string_to_map(rep, STR_KEY, ref_str);
	rt_response_send((rt_request_s *) request, rep, OCF_RESPONSE_CONTENT);
	rt_rep_encoder_release(rep);
}

TEST(test_coap_block, rt_coap_block2_send_NON_packet)
{
	//Given
	const char *uri_path = LIGHT_URI;
	rt_resource_s *resource = rt_res_new_resource(uri_path);
	rt_res_set_request_handler(resource, OCF_GET, get_handler_func);
	rt_res_register_resource(resource);

	uint16_t udp_normal_port_v4 = 0;
	rt_get_ports_v4(&udp_normal_port_v4, NULL, NULL, NULL);

	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", udp_normal_port_v4, OCF_UDP | OCF_IPV4);

	//When
	ocf_result_t ret = rt_request_get_send(&endpoint, LIGHT_URI, NULL, false, light_get_callback);

	//Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_INT(0, wait_for_condition(&g_mutex, &g_condition));
}

TEST(test_coap_block, rt_coap_block2_send_CON_packet)
{
	//Given
	const char *uri_path = LIGHT_URI;
	rt_resource_s *resource = rt_res_new_resource(uri_path);
	rt_res_set_request_handler(resource, OCF_GET, get_handler_func);
	rt_res_register_resource(resource);

	uint16_t udp_normal_port_v4 = 0;
	rt_get_ports_v4(&udp_normal_port_v4, NULL, NULL, NULL);

	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", udp_normal_port_v4, OCF_UDP | OCF_IPV4);

	//When
	ocf_result_t ret = rt_request_get_send(&endpoint, LIGHT_URI, NULL, true, light_get_callback);

	//Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_INT(0, wait_for_condition(&g_mutex, &g_condition));
}

static void block_post_handler_func(ocf_request_s request, ocf_rep_decoder_s data)
{
	RT_LOG_D(TAG, "IN : %s", __func__);

	rt_rep_encoder_s *rep = rt_rep_encoder_init(OCF_REP_MAP);
	rt_rep_add_int_to_map(rep, POWER_KEY, POWER_VALUE);
	rt_rep_add_string_to_map(rep, STR_KEY, ref_str);
	rt_response_send((rt_request_s *) request, rep, OCF_RESPONSE_CONTENT);
	rt_rep_encoder_release(rep);
}

static void combine_post_request(bool is_ack)
{
	//Given
	const char *uri_path = LIGHT_URI;
	rt_resource_s *resource = rt_res_new_resource(uri_path);
	rt_res_set_request_handler(resource, OCF_POST, block_post_handler_func);
	rt_res_register_resource(resource);

	uint16_t udp_normal_port_v4 = 0;
	rt_get_ports_v4(&udp_normal_port_v4, NULL, NULL, NULL);

	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", udp_normal_port_v4, OCF_UDP | OCF_IPV4);

	//When
	rt_rep_encoder_s *rep = rt_rep_encoder_init(OCF_REP_MAP);
	rt_rep_add_int_to_map(rep, POWER_KEY, POWER_VALUE);
	rt_rep_add_string_to_map(rep, STR_KEY, ref_str);

	ocf_result_t ret = rt_request_post_send(&endpoint, uri_path, NULL, rep, is_ack, light_post_callback);
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	rt_rep_encoder_release(rep);

	//Then
	TEST_ASSERT_EQUAL_INT(0, wait_for_condition(&g_mutex, &g_condition));
}

TEST(test_coap_block, rt_coap_block1_block2_combine_NON_test)
{
	combine_post_request(false);
}

TEST(test_coap_block, rt_coap_block1_block2_combine_CON_test)
{
	combine_post_request(true);
}

TEST_GROUP_RUNNER(test_coap_block)
{
	RUN_TEST_CASE(test_coap_block, rt_coap_block_init);
	RUN_TEST_CASE(test_coap_block, rt_coap_block_is_block_need_success)
	RUN_TEST_CASE(test_coap_block, rt_coap_block_is_block_need_fail_with_small_size)
	RUN_TEST_CASE(test_coap_block, rt_coap_block_is_block_need_fail_with_tcp_endpoint)
	RUN_TEST_CASE(test_coap_block, rt_coap_block1_send_NON_packet);
	RUN_TEST_CASE(test_coap_block, rt_coap_block1_send_CON_packet);
	RUN_TEST_CASE(test_coap_block, rt_coap_block2_send_NON_packet);
	RUN_TEST_CASE(test_coap_block, rt_coap_block2_send_CON_packet);
	RUN_TEST_CASE(test_coap_block, rt_coap_block1_block2_combine_NON_test);
	RUN_TEST_CASE(test_coap_block, rt_coap_block1_block2_combine_CON_test);
}

#ifndef CONFIG_ENABLE_RT_OCF

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_coap_block);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
