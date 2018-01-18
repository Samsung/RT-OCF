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

#include "rt_coap_constants.h"
#include "rt_coap_transactions.h"

#include "rt_logger.h"
#include "test_common.h"
#include "ocf_resources.h"

#define BUFSIZE 1024

static ocf_persistent_storage_handler_s temp_doxm_handler = { test_doxm_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_cred_handler = { test_cred_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_acl2_handler = { test_acl2_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_pstat_handler = { test_pstat_fopen, fread, fwrite, fclose };

TEST_GROUP(test_coap);

TEST_SETUP(test_coap)
{
	create_security_data_files();
	ocf_sec_register_ps_handler(&temp_doxm_handler, &temp_pstat_handler, &temp_cred_handler, &temp_acl2_handler);	
	ocf_init(OCF_CLIENT_SERVER, "Samsung", "1.0");
}

TEST_TEAR_DOWN(test_coap)
{
	ocf_terminate();
	remove_security_data_files();
}

TEST(test_coap, rt_coap_init_message)
{
	// given
	coap_packet_t msg[1];

	// when
	rt_coap_init_message(msg, COAP_TYPE_CON, COAP_GET, 1234);

	// then
	TEST_ASSERT_EQUAL_INT(msg[0].type, COAP_TYPE_CON);
	TEST_ASSERT_EQUAL_INT8(msg[0].code, COAP_GET);
	TEST_ASSERT_EQUAL_INT16(msg[0].mid, 1234);
}

TEST(test_coap, rt_coap_set_payload)
{
	// given
	coap_packet_t msg[1];
	char *payload = "1234";

	// when
	int actual = rt_coap_set_payload(msg, payload, 4);

	// then
	TEST_ASSERT_EQUAL_INT(4, actual);
}

TEST(test_coap, rt_coap_get_payload)
{
	// given
	coap_packet_t msg;
	rt_coap_set_payload(&msg, "1234", 4);

	// when
	const uint8_t *payload;
	int ret = rt_coap_get_payload(&msg, &payload);

	// then
	TEST_ASSERT_EQUAL_INT(4, ret);
	TEST_ASSERT_EQUAL_HEX8_ARRAY("1234", payload, 8);
}

TEST(test_coap, rt_coap_set_payload_REST_MAX_CHUNK_SIZE)
{
	// given
	coap_packet_t msg[1];
	char *payload = "1234";

	// when
	int actual = rt_coap_set_payload(msg, payload, REST_MAX_CHUNK_SIZE + 1);

	// then
	TEST_ASSERT_EQUAL_INT(REST_MAX_CHUNK_SIZE, actual);
}

TEST(test_coap, rt_coap_set_header_uri_path)
{
	// given
	coap_packet_t msg[1];
	const char *uri_path = ".well-known-core";

	// when
	int actual = rt_coap_set_header_uri_path(msg, uri_path);

	// then
	int expected_result = 16;
	TEST_ASSERT_EQUAL_INT(expected_result, actual);
	TEST_ASSERT_EQUAL_STRING(".well-known-core", msg[0].uri_path);
}

TEST(test_coap, rt_coap_get_header_uri_path)
{
	// given
	coap_packet_t msg[1];
	const char *expect_path = ".well-known-core";
	rt_coap_set_header_uri_path(msg, expect_path);

	// when
	const char *actual_path;
	int actual_ret = rt_coap_get_header_uri_path(msg, &actual_path);

	// then
	int path_len = 16;
	TEST_ASSERT_EQUAL_INT(path_len, actual_ret);
	TEST_ASSERT_EQUAL_STRING(expect_path, actual_path);
}

TEST(test_coap, rt_coap_set_header_uri_path_withslash)
{
	// given
	coap_packet_t msg[1];
	const char *uri_path = "////uri";

	// when
	int actual = rt_coap_set_header_uri_path(msg, uri_path);

	// then
	int expected_result = 3;
	TEST_ASSERT_EQUAL_INT(expected_result, actual);
	TEST_ASSERT_EQUAL_STRING("uri", msg[0].uri_path);
}

TEST(test_coap, rt_coap_serialize_message)
{
	// given
	uint16_t mid = 1234;
	coap_transaction_t t;
	coap_packet_t msg[1];

	const char *uri_path = ".well-known-core";
	const char *payload = "ABCED";
	uint8_t token[1] = { 0x11 };

	rt_coap_init_message(msg, COAP_TYPE_CON, COAP_GET, mid);
	rt_coap_set_payload(msg, payload, strlen(payload));
	rt_coap_set_header_uri_path(msg, uri_path);
	rt_coap_set_token(msg, token, sizeof(token));

	// when
	t.packet_len = rt_coap_serialize_message(msg, t.packet);

	// then
	char expected_result[8] = { 0x41, 0x01, 0x04, 0xD2, 0x11, 0xBD, 0x03, 0x2E };
	TEST_ASSERT_EQUAL_HEX8_ARRAY(expected_result, msg->buffer, 8);
}

TEST(test_coap, rt_coap_parse_message)
{
	// given
	coap_packet_t message[1];

	uint8_t packet[BUFSIZE] = {
		0x41, 0x01, 0x00, 0x0b, 0x11, 0xbd, 0x03, 0x2e, 0x77, 0x65, 0x6c, 0x6c, 0x2d, 0x6b, 0x6e, 0x6f,
		0x77, 0x6e, 0x2d, 0x63, 0x6f, 0x72, 0x65, 0xff, 0x41, 0x42, 0x43, 0x45, 0x44
	};

	uint16_t dataSize = 29;

	// when
	coap_status_t status_code = rt_coap_parse_message(message, packet, dataSize);
	TEST_ASSERT_EQUAL_INT(NO_ERROR, status_code);

	// then
	TEST_ASSERT_EQUAL_INT8(1, message->version);
	TEST_ASSERT_EQUAL_INT8(0, message->type);
	TEST_ASSERT_EQUAL_INT8(1, message->token.len);
	TEST_ASSERT_EQUAL_INT8(1, message->code);
	TEST_ASSERT_EQUAL_INT8(11, message->mid);
	TEST_ASSERT_EQUAL_STRING_LEN_MESSAGE(".well-known-core", message->uri_path, (int)message->uri_path_len, message->uri_path);
	TEST_ASSERT_EQUAL_STRING("ABCED", message->payload);
}


ocf_result_t test_coap_handler(struct _rt_data_s *data, const ocf_endpoint_s *endpoint)
{
	return OCF_OK;
}

TEST(test_coap, rt_coap_init)
{
	// given
	rt_coap_terminate();

	TEST_ASSERT_EQUAL_INT(OCF_OK, rt_coap_init(test_coap_handler, test_coap_handler));
}

TEST(test_coap, rt_coap_terminate)
{

	TEST_ASSERT_EQUAL_INT(OCF_OK, rt_coap_terminate());

	rt_coap_init(test_coap_handler, test_coap_handler);
}

TEST_GROUP_RUNNER(test_coap)
{
	RUN_TEST_CASE(test_coap, rt_coap_init_message);
	RUN_TEST_CASE(test_coap, rt_coap_set_payload);
	RUN_TEST_CASE(test_coap, rt_coap_get_payload);
	RUN_TEST_CASE(test_coap, rt_coap_set_payload_REST_MAX_CHUNK_SIZE);
	RUN_TEST_CASE(test_coap, rt_coap_set_header_uri_path);
	RUN_TEST_CASE(test_coap, rt_coap_set_header_uri_path_withslash);
	RUN_TEST_CASE(test_coap, rt_coap_get_header_uri_path);
	RUN_TEST_CASE(test_coap, rt_coap_serialize_message);
	RUN_TEST_CASE(test_coap, rt_coap_parse_message);
	RUN_TEST_CASE(test_coap, rt_coap_init);
	RUN_TEST_CASE(test_coap, rt_coap_terminate);
}

#ifndef CONFIG_IOTIVITY_RT

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_coap);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
