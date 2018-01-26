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
#include "rt_data_handler.h"
#include "rt_coap.h"
#include "rt_mem.h"
#include "rt_logger.h"

#define TAG "TC_RECV_DATA_HANDLER"

#define RESOURCE_URI "/data/handler"

TEST_GROUP(test_data_handler);

TEST_SETUP(test_data_handler)
{
	rt_mem_pool_init();
}

TEST_TEAR_DOWN(test_data_handler)
{
	rt_mem_pool_terminate();
}

TEST(test_data_handler, make_clone_data)
{
	rt_token_s token;
	token.len = TOKEN_LEN;
	rt_random_rand_to_buffer(token.token, token.len);
	const char *query = "rt=core.light";
	uint8_t *payload = (uint8_t *)"ABCDE";
	uint32_t payload_len = 5;

	rt_data_s expect_data = {
		.flags = RT_OPTION_TRANSACTION_REQUEST,
		.type = COAP_TYPE_CON,
		.code = COAP_GET,
		.observe_num = 0,
		.accept = OCF_1_0_0,
		.content_format = OCF_1_0_0,
		.mid = rt_coap_get_mid(),
		.token = token,
		.uri_path = RESOURCE_URI,
		.query = query,
		.payload = payload,
		.payload_len = payload_len
	};
	
	rt_data_s *actual_data = (rt_data_s *)rt_mem_alloc(sizeof(rt_data_s));
	
	ocf_result_t ret = rt_data_clone(actual_data, &expect_data);
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);

	TEST_ASSERT_EQUAL_INT(expect_data.flags, actual_data->flags);
	TEST_ASSERT_EQUAL_INT(expect_data.type, actual_data->type);
	TEST_ASSERT_EQUAL_INT(expect_data.code, actual_data->code);
	TEST_ASSERT_EQUAL_INT(expect_data.observe_num, actual_data->observe_num);
	TEST_ASSERT_EQUAL_INT(expect_data.accept, actual_data->accept);
	TEST_ASSERT_EQUAL_INT(expect_data.content_format, actual_data->content_format);
	TEST_ASSERT_EQUAL_INT(expect_data.mid, actual_data->mid);
	TEST_ASSERT_EQUAL_HEX8_ARRAY(expect_data.token.token, actual_data->token.token, expect_data.token.len);
	TEST_ASSERT_EQUAL_STRING_LEN(expect_data.uri_path, actual_data->uri_path, strlen(expect_data.uri_path));
	TEST_ASSERT_EQUAL_STRING_LEN(expect_data.query, actual_data->query, strlen(expect_data.query));
	TEST_ASSERT_EQUAL_HEX8_ARRAY(expect_data.payload, actual_data->payload, expect_data.payload_len);
	TEST_ASSERT_EQUAL_INT(expect_data.payload_len, actual_data->payload_len);

	rt_data_free_item(actual_data);
}


TEST(test_data_handler, make_receive_data)
{
	uint16_t mid = rt_coap_get_mid();
	coap_packet_t msg[1];
	rt_coap_init_message(msg, COAP_TYPE_CON, COAP_GET, mid);
	rt_coap_set_header_uri_path(msg, "/a/light");

	rt_token_s token;
	token.len = TOKEN_LEN;
	rt_random_rand_to_buffer(token.token, token.len);
	rt_coap_set_token(msg, token.token, token.len);
	rt_coap_set_header_uri_query(msg, "rt=core.light");

	rt_data_s *data = rt_receive_data_make_item(msg);

	TEST_ASSERT_NOT_NULL(data);
	rt_data_free_item(data);
}

TEST(test_data_handler, make_receive_data_with_invalid_param)
{
	rt_data_s *data = rt_receive_data_make_item(NULL);

	TEST_ASSERT_NULL(data);
}

TEST(test_data_handler, free_receive_data)
{
	uint16_t mid = rt_coap_get_mid();
	coap_packet_t msg[1];
	rt_coap_init_message(msg, COAP_TYPE_CON, COAP_GET, mid);
	rt_coap_set_header_uri_path(msg, "/a/light");

	rt_token_s token;
	token.len = TOKEN_LEN;
	rt_random_rand_to_buffer(token.token, token.len);
	rt_coap_set_token(msg, token.token, token.len);
	rt_coap_set_header_uri_query(msg, "rt=core.light");

	rt_data_s *data = rt_receive_data_make_item(msg);

	TEST_ASSERT_NOT_NULL(data);
	
	ocf_result_t ret = rt_data_free_item(data);
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
}

TEST(test_data_handler, create_token)
{
	rt_token_s token;
	rt_token_s token2;
	token.len = TOKEN_LEN;
	rt_random_rand_to_buffer(token.token, token.len);	
	printf("Token (len %u) [0x%02X%02X%02X%02X%02X%02X%02X%02X]\n", token.len, token.token[0], token.token[1], token.token[2], token.token[3], token.token[4], token.token[5],
	 token.token[6], token.token[7]
		  );		
	rt_coap_copy_token(&token2, &token);
	printf("Token (len %u) [0x%02X%02X%02X%02X%02X%02X%02X%02X]\n", token2.len, token2.token[0], token2.token[1], token2.token[2], token2.token[3], token2.token[4], token2.token[5],
	token2.token[6], token2.token[7]
		  );
}

TEST_GROUP_RUNNER(test_data_handler)
{
	RUN_TEST_CASE(test_data_handler, make_clone_data);
	RUN_TEST_CASE(test_data_handler, make_receive_data);
	RUN_TEST_CASE(test_data_handler, make_receive_data_with_invalid_param);
	RUN_TEST_CASE(test_data_handler, free_receive_data);
	RUN_TEST_CASE(test_data_handler, create_token);
}

#ifndef CONFIG_ENABLE_RT_OCF

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_data_handler);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
