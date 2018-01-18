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
#include "rt_mem.h"
#include "rt_logger.h"
#include "rt_rep.h"
#include "cbor.h"

#define TAG "TC_REP"

#define BUFFERSIZE 1024

TEST_GROUP(test_rep);

static ocf_rep_encoder_s rep_encoder;
static ocf_rep_decoder_s rep_decoder;

TEST_SETUP(test_rep)
{
	rep_encoder = NULL;
	rep_decoder = NULL;
}

TEST_TEAR_DOWN(test_rep)
{

	rt_rep_encoder_s *rt_rep_encoder = (rt_rep_encoder_s *) rep_encoder;

	rt_rep_encoder_log(rt_rep_encoder);

	ocf_rep_encoder_release(rep_encoder);
	if (rep_decoder) {
		ocf_rep_decoder_release(rep_decoder);
	}
}

// ADD
TEST(test_rep, rep_encoder_init)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);
	TEST_ASSERT_NOT_NULL(rep_encoder);
}

TEST(test_rep, check_duplicated_key)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);

	ocf_result_t ret = ocf_rep_add_int_to_map(rep_encoder, "age", 10);
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);

	ret = ocf_rep_add_int_to_map(rep_encoder, "age", 15);
	TEST_ASSERT_EQUAL_INT(OCF_ERROR, ret);
}

TEST(test_rep, mismatch_encoder_type)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);

	ocf_result_t ret = ocf_rep_add_int_to_map(rep_encoder, "age", 10);

	TEST_ASSERT_EQUAL_INT(OCF_ERROR, ret);
}

TEST(test_rep, check_added_item_count)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);

	ocf_rep_add_bool_to_map(rep_encoder, "power", true);
	ocf_rep_add_int_to_map(rep_encoder, "age", 10);
	ocf_rep_add_double_to_map(rep_encoder, "birth", 8.24);
	ocf_rep_add_string_to_map(rep_encoder, "name", "hong");

	rt_rep_encoder_s *rt_rep_encoder = (rt_rep_encoder_s *) rep_encoder;

	TEST_ASSERT_EQUAL_INT(4, rt_rep_encoder->count);

}

TEST(test_rep, add_boolean_to_map)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);

	ocf_result_t ret = ocf_rep_add_bool_to_map(rep_encoder, "power", true);

	RT_LOG_BUFFER_D(TAG, ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
}

TEST(test_rep, add_int_to_map)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);

	ocf_result_t ret = ocf_rep_add_int_to_map(rep_encoder, "age", 10);

	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
}

TEST(test_rep, add_double_to_map)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);

	ocf_result_t ret = ocf_rep_add_double_to_map(rep_encoder, "birth", 8.24);

	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
}

TEST(test_rep, add_string_to_map)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);

	ocf_result_t ret = ocf_rep_add_string_to_map(rep_encoder, "name", "hong");

	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
}

TEST(test_rep, add_byte_to_map)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);

	uint8_t byte[4] = { 0x41, 0x42, 0x43, 0x44 };
	ocf_result_t ret = ocf_rep_add_byte_to_map(rep_encoder, "byte", byte, 4);
	RT_LOG_BUFFER_D(TAG, ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
}

TEST(test_rep, add_map_to_map)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);

	ocf_rep_encoder_s sub = ocf_rep_encoder_init(OCF_REP_MAP);
	ocf_rep_add_int_to_map(sub, "key1", 10);
	ocf_rep_add_int_to_map(sub, "key2", 20);
	ocf_rep_add_int_to_map(sub, "key3", 30);

	ocf_result_t ret = ocf_rep_add_map_to_map(rep_encoder, "map", sub);

	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	ocf_rep_encoder_release(sub);
}

TEST(test_rep, add_array_to_map)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);
	ocf_rep_encoder_s sub = ocf_rep_encoder_init(OCF_REP_ARRAY);
	ocf_rep_add_int_to_array(sub, 10);
	ocf_rep_add_int_to_array(sub, 20);
	ocf_rep_add_int_to_array(sub, 30);

	ocf_result_t ret = ocf_rep_add_array_to_map(rep_encoder, "array", sub);

	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);

	ocf_rep_encoder_release(sub);
}

TEST(test_rep, add_boolean_to_array)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);

	ocf_result_t ret = ocf_rep_add_bool_to_array(rep_encoder, true);

	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
}

TEST(test_rep, add_int_to_array)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);

	ocf_result_t ret = ocf_rep_add_int_to_array(rep_encoder, 10);

	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
}

TEST(test_rep, add_int_to_array_full)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);
	int i;
	for (i = 0; i < MAX_ITEM_COUNT; i++) {
		ocf_rep_add_int_to_array(rep_encoder, i);
	}

	ocf_result_t ret = ocf_rep_add_int_to_array(rep_encoder, i);

	TEST_ASSERT_EQUAL_INT(OCF_ERROR, ret);
}

TEST(test_rep, add_double_to_array)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);

	ocf_result_t ret = ocf_rep_add_double_to_array(rep_encoder, 8.24);

	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
}

TEST(test_rep, add_string_to_array)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);

	ocf_result_t ret = ocf_rep_add_string_to_array(rep_encoder, "hong");

	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
}

TEST(test_rep, add_byte_to_array)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);

	uint8_t byte[4] = { 0x41, 0x42, 0x43, 0x44 };
	ocf_result_t ret = ocf_rep_add_byte_to_array(rep_encoder, byte, 4);
	RT_LOG_BUFFER_D(TAG, ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
}

TEST(test_rep, add_map_to_array)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);

	ocf_rep_encoder_s sub = ocf_rep_encoder_init(OCF_REP_MAP);
	ocf_rep_add_int_to_map(sub, "key1", 10);
	ocf_rep_add_int_to_map(sub, "key2", 20);
	ocf_rep_add_int_to_map(sub, "key3", 30);

	ocf_result_t ret = ocf_rep_add_map_to_array(rep_encoder, sub);

	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	ocf_rep_encoder_release(sub);
}

TEST(test_rep, add_array_to_array)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);

	ocf_rep_encoder_s sub = ocf_rep_encoder_init(OCF_REP_ARRAY);
	ocf_rep_add_int_to_array(sub, 10);
	ocf_rep_add_int_to_array(sub, 20);
	ocf_rep_add_int_to_array(sub, 30);

	ocf_result_t ret = ocf_rep_add_array_to_array(rep_encoder, sub);

	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	ocf_rep_encoder_release(sub);
}

// GET
TEST(test_rep, rep_decoder_init)
{
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);

	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	TEST_ASSERT_NOT_EQUAL(NULL, rep_decoder);
}

// GET From MAP
TEST(test_rep, get_boolean_value_from_map)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);
	ocf_rep_add_bool_to_map(rep_encoder, "power", true);

	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	bool result;
	ocf_result_t ret = ocf_rep_get_bool_from_map(rep_decoder, "power", &result);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_TRUE(result);
}

TEST(test_rep, get_int_value_from_map)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);
	ocf_rep_add_int_to_map(rep_encoder, "power", 123);
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	int result;
	ocf_result_t ret = ocf_rep_get_int_from_map(rep_decoder, "power", &result);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_INT(123, result);
}

TEST(test_rep, get_double_value_from_map)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);
	ocf_rep_add_double_to_map(rep_encoder, "power", 8.1);
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	double result;
	ocf_result_t ret = ocf_rep_get_double_from_map(rep_decoder, "power", &result);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_DOUBLE(8.1, result);
}

TEST(test_rep, get_int_value_with_invalid_key_from_map)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);
	ocf_rep_add_int_to_map(rep_encoder, "power", 123);
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	int result;
	ocf_result_t ret = ocf_rep_get_int_from_map(rep_decoder, "invalid", &result);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, ret);
}

TEST(test_rep, get_string_value_from_map)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);
	ocf_rep_add_string_to_map(rep_encoder, "name", "hong");
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	size_t len;
	ocf_rep_get_string_length_from_map(rep_decoder, "name", &len);
	char *result = rt_mem_alloc(len + 1);
	ocf_result_t ret = ocf_rep_get_string_from_map(rep_decoder, "name", result);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_STRING("hong", result);

	rt_mem_free(result);
}

TEST(test_rep, get_string_value_with_null_from_map)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);
	ocf_rep_add_string_to_map(rep_encoder, "name", "hong");
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	char *result = NULL;
	ocf_result_t ret = ocf_rep_get_string_from_map(rep_decoder, "name", result);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, ret);
}

TEST(test_rep, get_byte_length_from_map)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);
	uint8_t byte[4] = { 0x41, 0x42, 0x43, 0x44 };
	ocf_rep_add_byte_to_map(rep_encoder, "byte", byte, 4);
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	size_t len;
	ocf_result_t ret = ocf_rep_get_byte_length_from_map(rep_decoder, "byte", &len);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_INT(4, len);
}

TEST(test_rep, get_byte_from_map)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);
	uint8_t byte[4] = { 0x41, 0x42, 0x43, 0x44 };
	ocf_rep_add_byte_to_map(rep_encoder, "byte", byte, 4);
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	uint8_t result[4];
	ocf_result_t ret = ocf_rep_get_byte_from_map(rep_decoder, "byte", result);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(byte, result, 4);
}

TEST(test_rep, get_map_from_map)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);

	ocf_rep_encoder_s sub = ocf_rep_encoder_init(OCF_REP_MAP);
	ocf_rep_add_string_to_map(sub, "name", "hong");
	ocf_rep_add_int_to_map(sub, "age", 31);
	ocf_rep_add_double_to_map(sub, "birth", 8.10);
	ocf_rep_add_map_to_map(rep_encoder, "key1", sub);

	ocf_rep_encoder_s sub2 = ocf_rep_encoder_init(OCF_REP_MAP);
	ocf_rep_add_string_to_map(sub2, "name", "guni");
	ocf_rep_add_int_to_map(sub2, "age", 30);
	ocf_rep_add_double_to_map(sub2, "birth", 12.31);
	ocf_rep_add_map_to_map(rep_encoder, "key2", sub2);

	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When

	ocf_rep_decoder_s result[2];
	rt_rep_decoder_s rt_result[2];

	result[0] = (ocf_rep_decoder_s) & rt_result[0];
	result[1] = (ocf_rep_decoder_s) & rt_result[1];

	ocf_result_t ret = ocf_rep_get_map_from_map(rep_decoder, "key1", result[0]);
	ret |= ocf_rep_get_map_from_map(rep_decoder, "key2", result[1]);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	int age;
	ocf_rep_get_int_from_map(result[0], "age", &age);
	TEST_ASSERT_EQUAL_INT(31, age);
	ocf_rep_get_int_from_map(result[1], "age", &age);
	TEST_ASSERT_EQUAL_INT(30, age);

	double birth;
	ocf_rep_get_double_from_map(result[0], "birth", &birth);
	TEST_ASSERT_EQUAL_DOUBLE(8.10, birth);
	ocf_rep_get_double_from_map(result[1], "birth", &birth);
	TEST_ASSERT_EQUAL_DOUBLE(12.31, birth);

	ocf_rep_encoder_release(sub);
	ocf_rep_encoder_release(sub2);
}

TEST(test_rep, get_array_from_map)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_MAP);

	ocf_rep_encoder_s sub = ocf_rep_encoder_init(OCF_REP_ARRAY);
	ocf_rep_add_bool_to_array(sub, true);
	ocf_rep_add_bool_to_array(sub, false);
	ocf_rep_add_bool_to_array(sub, true);
	ocf_rep_add_array_to_map(rep_encoder, "key1", sub);

	ocf_rep_encoder_s sub2 = ocf_rep_encoder_init(OCF_REP_ARRAY);
	ocf_rep_add_int_to_array(sub2, 1);
	ocf_rep_add_int_to_array(sub2, 2);
	ocf_rep_add_int_to_array(sub2, 3);
	ocf_rep_add_array_to_map(rep_encoder, "key2", sub2);

	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	ocf_rep_decoder_s result[2];
	rt_rep_decoder_s rt_result[2];
	result[0] = (ocf_rep_decoder_s) & rt_result[0];
	result[1] = (ocf_rep_decoder_s) & rt_result[1];

	ocf_result_t ret = ocf_rep_get_array_from_map(rep_decoder, "key1", result[0]);
	ret |= ocf_rep_get_array_from_map(rep_decoder, "key2", result[1]);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	bool bool_result[3];

	ocf_rep_get_bool_array(result[0], 3, bool_result);
	TEST_ASSERT_TRUE(bool_result[0]);
	TEST_ASSERT_FALSE(bool_result[1]);
	TEST_ASSERT_TRUE(bool_result[2]);

	int int_result[3];
	ocf_rep_get_int_array(result[1], 3, int_result);
	TEST_ASSERT_EQUAL_INT(1, int_result[0]);
	TEST_ASSERT_EQUAL_INT(2, int_result[1]);
	TEST_ASSERT_EQUAL_INT(3, int_result[2]);

	ocf_rep_encoder_release(sub);
	ocf_rep_encoder_release(sub2);
}

TEST(test_rep, get_array_length)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);
	ocf_rep_add_bool_to_array(rep_encoder, true);
	ocf_rep_add_bool_to_array(rep_encoder, false);
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	uint16_t size = 0;
	ocf_result_t ret = ocf_rep_get_array_length(rep_decoder, &size);

	// Then
	TEST_ASSERT_EQUAL_INT(2, size);
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
}

TEST(test_rep, get_array_length_twice)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);
	ocf_rep_add_bool_to_array(rep_encoder, true);
	ocf_rep_add_bool_to_array(rep_encoder, false);
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	uint16_t size = 0;
	ocf_result_t ret = ocf_rep_get_array_length(rep_decoder, &size);
	ret = ocf_rep_get_array_length(rep_decoder, &size);

	// Then
	TEST_ASSERT_EQUAL_INT(2, size);
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
}

// GET From Array
TEST(test_rep, get_boolean_from_array)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);
	ocf_rep_add_bool_to_array(rep_encoder, true);
	ocf_rep_add_bool_to_array(rep_encoder, false);
	ocf_rep_add_bool_to_array(rep_encoder, true);
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	bool result[3];
	ocf_result_t ret = ocf_rep_get_bool_from_array(rep_decoder, 0, &result[0]);
	ret |= ocf_rep_get_bool_from_array(rep_decoder, 1, &result[1]);
	ret |= ocf_rep_get_bool_from_array(rep_decoder, 2, &result[2]);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_TRUE(result[0]);
	TEST_ASSERT_FALSE(result[1]);
	TEST_ASSERT_TRUE(result[2]);
}

TEST(test_rep, get_int_from_array)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);
	ocf_rep_add_int_to_array(rep_encoder, 1);
	ocf_rep_add_int_to_array(rep_encoder, 2);
	ocf_rep_add_int_to_array(rep_encoder, 3);
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	int result[3];
	ocf_result_t ret = ocf_rep_get_int_from_array(rep_decoder, 0, &result[0]);
	ret |= ocf_rep_get_int_from_array(rep_decoder, 1, &result[1]);
	ret |= ocf_rep_get_int_from_array(rep_decoder, 2, &result[2]);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_INT(1, result[0]);
	TEST_ASSERT_EQUAL_INT(2, result[1]);
	TEST_ASSERT_EQUAL_INT(3, result[2]);
}

TEST(test_rep, get_double_from_array)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);
	ocf_rep_add_double_to_array(rep_encoder, 2.12);
	ocf_rep_add_double_to_array(rep_encoder, 9.15);
	ocf_rep_add_double_to_array(rep_encoder, 12.16);
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	double result[3];
	ocf_result_t ret = ocf_rep_get_double_from_array(rep_decoder, 0, &result[0]);
	ret |= ocf_rep_get_double_from_array(rep_decoder, 1, &result[1]);
	ret |= ocf_rep_get_double_from_array(rep_decoder, 2, &result[2]);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_DOUBLE(2.12, result[0]);
	TEST_ASSERT_EQUAL_DOUBLE(9.15, result[1]);
	TEST_ASSERT_EQUAL_DOUBLE(12.16, result[2]);
}

TEST(test_rep, get_string_from_array)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);
	ocf_rep_add_string_to_array(rep_encoder, "oic.r.power");
	ocf_rep_add_string_to_array(rep_encoder, "oic.r.temperature");
	ocf_rep_add_string_to_array(rep_encoder, "oic.r.humidity");
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	size_t len[3];
	ocf_rep_get_string_length_from_array(rep_decoder, 0, &len[0]);
	ocf_rep_get_string_length_from_array(rep_decoder, 1, &len[1]);
	ocf_rep_get_string_length_from_array(rep_decoder, 2, &len[2]);

	char *result[3];
	result[0] = (char *)rt_mem_alloc(sizeof(char) * (len[0] + 1));
	result[1] = (char *)rt_mem_alloc(sizeof(char) * (len[1] + 1));
	result[2] = (char *)rt_mem_alloc(sizeof(char) * (len[2] + 1));
	ocf_result_t ret = ocf_rep_get_string_from_array(rep_decoder, 0, result[0]);
	ret |= ocf_rep_get_string_from_array(rep_decoder, 1, result[1]);
	ret |= ocf_rep_get_string_from_array(rep_decoder, 2, result[2]);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_STRING("oic.r.power", result[0]);
	TEST_ASSERT_EQUAL_STRING("oic.r.temperature", result[1]);
	TEST_ASSERT_EQUAL_STRING("oic.r.humidity", result[2]);

	rt_mem_free(result[0]);
	rt_mem_free(result[1]);
	rt_mem_free(result[2]);
}

TEST(test_rep, get_byte_length_from_array)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);
	uint8_t byte[4] = { 0x41, 0x42, 0x43, 0x44 };
	ocf_rep_add_byte_to_array(rep_encoder, byte, 4);
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	size_t len;
	ocf_result_t ret = ocf_rep_get_byte_length_from_array(rep_decoder, 0, &len);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_INT(4, len);
}

TEST(test_rep, get_byte_from_array)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);
	uint8_t byte[4] = { 0x41, 0x42, 0x43, 0x44 };
	ocf_rep_add_byte_to_array(rep_encoder, byte, 4);
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	uint8_t result[4];
	ocf_result_t ret = ocf_rep_get_byte_from_array(rep_decoder, 0, result);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(byte, result, 4);
}

TEST(test_rep, get_map_from_array)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);

	ocf_rep_encoder_s sub = ocf_rep_encoder_init(OCF_REP_MAP);
	ocf_rep_add_string_to_map(sub, "name", "hong");
	ocf_rep_add_int_to_map(sub, "age", 31);
	ocf_rep_add_double_to_map(sub, "birth", 8.10);
	ocf_rep_add_map_to_array(rep_encoder, sub);

	ocf_rep_encoder_s sub2 = ocf_rep_encoder_init(OCF_REP_MAP);
	ocf_rep_add_string_to_map(sub2, "name", "guni");
	ocf_rep_add_int_to_map(sub2, "age", 30);
	ocf_rep_add_double_to_map(sub2, "birth", 12.31);
	ocf_rep_add_map_to_array(rep_encoder, sub2);

	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	rt_rep_decoder_s rt_result[2];
	ocf_rep_decoder_s result[2];

	result[0] = (ocf_rep_decoder_s) & rt_result[0];
	result[1] = (ocf_rep_decoder_s) & rt_result[1];

	ocf_result_t ret = ocf_rep_get_map_from_array(rep_decoder, 0, result[0]);
	ret |= ocf_rep_get_map_from_array(rep_decoder, 1, result[1]);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	int age[2];
	ocf_rep_get_int_from_map(result[0], "age", &age[0]);
	TEST_ASSERT_EQUAL_INT(31, age[0]);
	ocf_rep_get_int_from_map(result[1], "age", &age[1]);
	TEST_ASSERT_EQUAL_INT(30, age[1]);
	double birth[2];
	ocf_rep_get_double_from_map(result[0], "birth", &birth[0]);
	TEST_ASSERT_EQUAL_DOUBLE(8.10, birth[0]);
	ocf_rep_get_double_from_map(result[1], "birth", &birth[1]);
	TEST_ASSERT_EQUAL_DOUBLE(12.31, birth[1]);

	ocf_rep_encoder_release(sub);
	ocf_rep_encoder_release(sub2);
}

TEST(test_rep, get_array_from_array)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);

	ocf_rep_encoder_s sub = ocf_rep_encoder_init(OCF_REP_ARRAY);
	ocf_rep_add_bool_to_array(sub, true);
	ocf_rep_add_bool_to_array(sub, false);
	ocf_rep_add_bool_to_array(sub, true);
	ocf_rep_add_array_to_array(rep_encoder, sub);

	ocf_rep_encoder_s sub2 = ocf_rep_encoder_init(OCF_REP_ARRAY);
	ocf_rep_add_int_to_array(sub2, 1);
	ocf_rep_add_int_to_array(sub2, 2);
	ocf_rep_add_int_to_array(sub2, 3);
	ocf_rep_add_array_to_array(rep_encoder, sub2);

	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	rt_rep_decoder_s rt_result[2];
	ocf_rep_decoder_s result[2];

	result[0] = (ocf_rep_decoder_s) & rt_result[0];
	result[1] = (ocf_rep_decoder_s) & rt_result[1];

	ocf_result_t ret = ocf_rep_get_array_from_array(rep_decoder, 0, result[0]);
	ret |= ocf_rep_get_array_from_array(rep_decoder, 1, result[1]);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	bool bool_result[3];
	ocf_rep_get_bool_array(result[0], 3, bool_result);
	TEST_ASSERT_TRUE(bool_result[0]);
	TEST_ASSERT_FALSE(bool_result[1]);
	TEST_ASSERT_TRUE(bool_result[2]);

	int int_result[3];
	ocf_rep_get_int_array(result[1], 3, int_result);
	TEST_ASSERT_EQUAL_INT(1, int_result[0]);
	TEST_ASSERT_EQUAL_INT(2, int_result[1]);
	TEST_ASSERT_EQUAL_INT(3, int_result[2]);

	ocf_rep_encoder_release(sub);
	ocf_rep_encoder_release(sub2);
}

TEST(test_rep, get_boolean_array)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);
	ocf_rep_add_bool_to_array(rep_encoder, true);
	ocf_rep_add_bool_to_array(rep_encoder, false);
	ocf_rep_add_bool_to_array(rep_encoder, true);
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	uint16_t size = 3;
	bool *result = (bool *) rt_mem_alloc(sizeof(bool) * size);
	ocf_result_t ret = ocf_rep_get_bool_array(rep_decoder, size, result);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_TRUE(result[0]);
	TEST_ASSERT_FALSE(result[1]);
	TEST_ASSERT_TRUE(result[2]);

	rt_mem_free(result);
}

TEST(test_rep, get_int_array)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);
	ocf_rep_add_int_to_array(rep_encoder, 1);
	ocf_rep_add_int_to_array(rep_encoder, 2);
	ocf_rep_add_int_to_array(rep_encoder, 3);
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	uint16_t size = 3;
	int *result = (int *)rt_mem_alloc(sizeof(int) * size);
	ocf_result_t ret = ocf_rep_get_int_array(rep_decoder, size, result);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_INT(1, result[0]);
	TEST_ASSERT_EQUAL_INT(2, result[1]);
	TEST_ASSERT_EQUAL_INT(3, result[2]);

	rt_mem_free(result);
}

TEST(test_rep, get_double_array)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);
	ocf_rep_add_double_to_array(rep_encoder, 2.12);
	ocf_rep_add_double_to_array(rep_encoder, 9.15);
	ocf_rep_add_double_to_array(rep_encoder, 12.16);
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	uint16_t size = 3;
	double *result = (double *)rt_mem_alloc(sizeof(double) * size);
	ocf_result_t ret = ocf_rep_get_double_array(rep_decoder, size, result);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_DOUBLE(2.12, result[0]);
	TEST_ASSERT_EQUAL_DOUBLE(9.15, result[1]);
	TEST_ASSERT_EQUAL_DOUBLE(12.16, result[2]);

	rt_mem_free(result);
}

TEST(test_rep, get_string_array)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);
	ocf_rep_add_string_to_array(rep_encoder, "oic.r.power");
	ocf_rep_add_string_to_array(rep_encoder, "oic.r.temperature");
	ocf_rep_add_string_to_array(rep_encoder, "oic.r.humidity");
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	char *result[3];
	result[0] = (char *)rt_mem_alloc(sizeof(char) * 20);
	result[1] = (char *)rt_mem_alloc(sizeof(char) * 20);
	result[2] = (char *)rt_mem_alloc(sizeof(char) * 20);
	ocf_result_t ret = ocf_rep_get_string_array(rep_decoder, 3, result);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_STRING("oic.r.power", result[0]);
	TEST_ASSERT_EQUAL_STRING("oic.r.temperature", result[1]);
	TEST_ASSERT_EQUAL_STRING("oic.r.humidity", result[2]);

	rt_mem_free(result[0]);
	rt_mem_free(result[1]);
	rt_mem_free(result[2]);
}

TEST(test_rep, get_byte_array)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);
	uint8_t byte[2][4] = { {0x41, 0x42, 0x43, 0x44}, {0x45, 0x46, 0x47, 0x48} };
	ocf_rep_add_byte_to_array(rep_encoder, byte[0], 4);
	ocf_rep_add_byte_to_array(rep_encoder, byte[1], 4);
	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	uint8_t *result[2];
	result[0] = (uint8_t *) rt_mem_alloc(sizeof(uint8_t) * 4);
	result[1] = (uint8_t *) rt_mem_alloc(sizeof(uint8_t) * 4);
	ocf_result_t ret = ocf_rep_get_byte_array(rep_decoder, 2, result);

	// // Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(byte[0], result[0], 4);
	TEST_ASSERT_EQUAL_UINT8_ARRAY(byte[1], result[1], 4);

	rt_mem_free(result[0]);
	rt_mem_free(result[1]);
}

TEST(test_rep, get_map_array)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);

	ocf_rep_encoder_s sub = ocf_rep_encoder_init(OCF_REP_MAP);
	ocf_rep_add_string_to_map(sub, "name", "hong");
	ocf_rep_add_int_to_map(sub, "age", 31);
	ocf_rep_add_double_to_map(sub, "birth", 8.10);
	ocf_rep_add_map_to_array(rep_encoder, sub);

	ocf_rep_encoder_s sub2 = ocf_rep_encoder_init(OCF_REP_MAP);
	ocf_rep_add_string_to_map(sub2, "name", "guni");
	ocf_rep_add_int_to_map(sub2, "age", 30);
	ocf_rep_add_double_to_map(sub2, "birth", 12.31);
	ocf_rep_add_map_to_array(rep_encoder, sub2);

	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When

	rt_rep_decoder_s rt_result[2];
	ocf_rep_decoder_s result[2];

	ocf_result_t ret = ocf_rep_get_map_array(rep_decoder, 2, (ocf_rep_decoder_s) rt_result);

	result[0] = (ocf_rep_decoder_s) & rt_result[0];
	result[1] = (ocf_rep_decoder_s) & rt_result[1];

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	int age[2];
	ocf_rep_get_int_from_map(result[0], "age", &age[0]);
	TEST_ASSERT_EQUAL_INT(31, age[0]);
	ocf_rep_get_int_from_map(result[1], "age", &age[1]);
	TEST_ASSERT_EQUAL_INT(30, age[1]);
	double birth[2];
	ocf_rep_get_double_from_map(result[0], "birth", &birth[0]);
	TEST_ASSERT_EQUAL_DOUBLE(8.10, birth[0]);
	ocf_rep_get_double_from_map(result[1], "birth", &birth[1]);
	TEST_ASSERT_EQUAL_DOUBLE(12.31, birth[1]);

	ocf_rep_encoder_release(sub);
	ocf_rep_encoder_release(sub2);
}

TEST(test_rep, get_array_array)
{
	// Given
	rep_encoder = ocf_rep_encoder_init(OCF_REP_ARRAY);

	ocf_rep_encoder_s sub = ocf_rep_encoder_init(OCF_REP_ARRAY);
	ocf_rep_add_bool_to_array(sub, true);
	ocf_rep_add_bool_to_array(sub, false);
	ocf_rep_add_bool_to_array(sub, true);
	ocf_rep_add_array_to_array(rep_encoder, sub);

	ocf_rep_encoder_s sub2 = ocf_rep_encoder_init(OCF_REP_ARRAY);
	ocf_rep_add_int_to_array(sub2, 1);
	ocf_rep_add_int_to_array(sub2, 2);
	ocf_rep_add_int_to_array(sub2, 3);
	ocf_rep_add_array_to_array(rep_encoder, sub2);

	rep_decoder = ocf_rep_decoder_init(ocf_rep_decoder_get_payload_addr(rep_encoder), ocf_rep_decoder_get_payload_size(rep_encoder));

	// When
	ocf_rep_decoder_s result[2];
	rt_rep_decoder_s rt_result[2];

	ocf_result_t ret = ocf_rep_get_array_array(rep_decoder, 2, (ocf_rep_decoder_s) rt_result);

	result[0] = (ocf_rep_decoder_s) & rt_result[0];
	result[1] = (ocf_rep_decoder_s) & rt_result[1];

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	bool bool_result[3];
	ocf_rep_get_bool_array(result[0], 3, bool_result);
	TEST_ASSERT_TRUE(bool_result[0]);
	TEST_ASSERT_FALSE(bool_result[1]);
	TEST_ASSERT_TRUE(bool_result[2]);

	int int_result[3];
	ocf_rep_get_int_array(result[1], 3, int_result);
	TEST_ASSERT_EQUAL_INT(1, int_result[0]);
	TEST_ASSERT_EQUAL_INT(2, int_result[1]);
	TEST_ASSERT_EQUAL_INT(3, int_result[2]);

	ocf_rep_encoder_release(sub);
	ocf_rep_encoder_release(sub2);
}

TEST_GROUP_RUNNER(test_rep)
{
	rt_mem_pool_init();
	// Add
	RUN_TEST_CASE(test_rep, rep_encoder_init);
	RUN_TEST_CASE(test_rep, check_duplicated_key);
	RUN_TEST_CASE(test_rep, mismatch_encoder_type);
	RUN_TEST_CASE(test_rep, check_added_item_count);
	// Add - Map
	RUN_TEST_CASE(test_rep, add_boolean_to_map);
	RUN_TEST_CASE(test_rep, add_int_to_map);
	RUN_TEST_CASE(test_rep, add_double_to_map);
	RUN_TEST_CASE(test_rep, add_string_to_map);
	RUN_TEST_CASE(test_rep, add_byte_to_map);
	RUN_TEST_CASE(test_rep, add_map_to_map);
	RUN_TEST_CASE(test_rep, add_array_to_map);
	// Add - Array
	RUN_TEST_CASE(test_rep, add_boolean_to_array);
	RUN_TEST_CASE(test_rep, add_int_to_array);
	RUN_TEST_CASE(test_rep, add_int_to_array_full);
	RUN_TEST_CASE(test_rep, add_double_to_array);
	RUN_TEST_CASE(test_rep, add_string_to_array);
	RUN_TEST_CASE(test_rep, add_byte_to_array);
	RUN_TEST_CASE(test_rep, add_map_to_array);
	RUN_TEST_CASE(test_rep, add_array_to_array);

	// Get
	RUN_TEST_CASE(test_rep, rep_decoder_init);
	// Get - Map
	RUN_TEST_CASE(test_rep, get_boolean_value_from_map);
	RUN_TEST_CASE(test_rep, get_int_value_from_map);
	RUN_TEST_CASE(test_rep, get_int_value_with_invalid_key_from_map);
	RUN_TEST_CASE(test_rep, get_double_value_from_map);
	RUN_TEST_CASE(test_rep, get_string_value_from_map);
	RUN_TEST_CASE(test_rep, get_string_value_with_null_from_map);
	RUN_TEST_CASE(test_rep, get_byte_length_from_map);
	RUN_TEST_CASE(test_rep, get_byte_from_map);
	RUN_TEST_CASE(test_rep, get_map_from_map);
	RUN_TEST_CASE(test_rep, get_array_from_map);

	// Get - Array
	RUN_TEST_CASE(test_rep, get_array_length);
	RUN_TEST_CASE(test_rep, get_array_length_twice);
	// Get - Array/index
	RUN_TEST_CASE(test_rep, get_boolean_from_array);
	RUN_TEST_CASE(test_rep, get_int_from_array);
	RUN_TEST_CASE(test_rep, get_double_from_array);
	RUN_TEST_CASE(test_rep, get_string_from_array);
	RUN_TEST_CASE(test_rep, get_byte_length_from_array);
	RUN_TEST_CASE(test_rep, get_byte_from_array);
	RUN_TEST_CASE(test_rep, get_map_from_array);
	RUN_TEST_CASE(test_rep, get_array_from_array);

	// Get - Array/size
	RUN_TEST_CASE(test_rep, get_boolean_array);
	RUN_TEST_CASE(test_rep, get_int_array);
	RUN_TEST_CASE(test_rep, get_double_array);
	RUN_TEST_CASE(test_rep, get_string_array);
	RUN_TEST_CASE(test_rep, get_byte_array);
	RUN_TEST_CASE(test_rep, get_map_array);
	RUN_TEST_CASE(test_rep, get_array_array);

	rt_mem_pool_terminate();
}

#ifndef CONFIG_IOTIVITY_RT

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_rep);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
