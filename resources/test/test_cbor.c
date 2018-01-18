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
#include "rt_logger.h"
#include "cbor.h"

#define TAG "TC_CBOR"

TEST_GROUP(test_cbor);

TEST_SETUP(test_cbor)
{
}

TEST_TEAR_DOWN(test_cbor)
{
}

#define BUFSIZE 32

/*[
   {
   "di" : UUID,
   "rt": ["oic.wk.res"],
   "n":"MyDevice",
   }
   ]
 */

TEST(test_cbor, init)
{
	CborEncoder encoder;
	uint8_t buffer[BUFSIZE];
	size_t size = BUFSIZE;

	memset(buffer, 0, size);
	RT_LOG_BUFFER_I(TAG, buffer, size);

	// Encoding
	cbor_encoder_init(&encoder, buffer, size, 0);

	CborEncoder root_array_encoder;
	cbor_encoder_create_array(&encoder, &root_array_encoder, 1);
	CborEncoder root_map_encoder;
	cbor_encoder_create_map(&root_array_encoder, &root_map_encoder, CborIndefiniteLength);
	cbor_encode_text_string(&root_map_encoder, "di", 2);
	cbor_encode_text_string(&root_map_encoder, "UUID", 4);
	cbor_encoder_close_container(&root_array_encoder, &root_map_encoder);
	cbor_encoder_close_container(&encoder, &root_array_encoder);

	RT_LOG_BUFFER_I(TAG, buffer, size);
	size_t encoded_size = cbor_encoder_get_buffer_size(&encoder, buffer);
	RT_LOG_I(TAG, "encoded size %d", encoded_size);

	// Decoding
	// CborParser parser;
	// CborValue root_value;
	// CborValue* root_arr_value = &root_value;
	// cbor_parser_init(buffer, encoded_size, 0, &parser, &root_value);
	// cbor_value_enter_container(&root_value, &root_arr_value);
}

TEST_GROUP_RUNNER(test_cbor)
{
	RUN_TEST_CASE(test_cbor, init);
}

#ifndef CONFIG_IOTIVITY_RT

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_cbor);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
