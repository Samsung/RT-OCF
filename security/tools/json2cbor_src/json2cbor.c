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

/*
 * Summary of modifications from original source code
 * - cJSON_Number case is more specified with else if.
 * - cJSON_RAW case is added into cjson_cbor_stream_decode().
 * - Parsing code for new data part is added into cJSON_Object case.
 */

/*
 * Contributed by Jacob Teplitsky <jacob.teplitsky@ericsson.com>
 *
 * libcbor is free software; you can redistribute it and/or modify
 * it under the terms of the MIT license. See LICENSE for details.
 */

/**
 * This code demonstrates how cJSON (https://github.com/DaveGamble/cJSON) callbacks
 * can be used in conjuction with the streaming parser to translate JSON to CBOR.
 * Please note that cbor_builder_* APIs are internal and thus subject to change.
 *
 * The example will only be compiled when cJSON is available
 */

#include <string.h>
#include <math.h>
#include <float.h>
#include "cJSON.h"
#include "cbor.h"
#include "builder_callbacks.h"
#include "loaders.h"

typedef void (*cbor_load_callback_t)(cJSON *, const struct cbor_callbacks *, void *);

static unsigned int toInt(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'A' && c <= 'F') {
		return 10 + c - 'A';
	}
	if (c >= 'a' && c <= 'f') {
		return 10 + c - 'a';
	}
	return -1;
}

cbor_item_t *cjson_cbor_load(void *source, cbor_load_callback_t cbor_load_callback)
{
	static struct cbor_callbacks callbacks = {
		.uint64 = &cbor_builder_uint64_callback,
		.negint64 = &cbor_builder_negint64_callback,
		.uint8 = &cbor_builder_uint8_callback,
		.negint8 = &cbor_builder_negint8_callback,
		.uint16 = &cbor_builder_uint16_callback,
		.negint16 = &cbor_builder_negint16_callback,
		.uint32 = &cbor_builder_uint32_callback,
		.negint32 = &cbor_builder_negint32_callback,
		.string = &cbor_builder_string_callback,
		.byte_string = &cbor_builder_byte_string_callback,
		.array_start = &cbor_builder_array_start_callback,
		.map_start = &cbor_builder_map_start_callback,
		.null = &cbor_builder_null_callback,
		.boolean = &cbor_builder_boolean_callback,
		.float4 = &cbor_builder_float4_callback,
	};

	/* Context stack */
	struct _cbor_stack stack = _cbor_stack_init();

	/* Target for callbacks */
	struct _cbor_decoder_context context = (struct _cbor_decoder_context) {
		.stack = &stack,
	};

	cbor_load_callback(source, &callbacks, &context);

	return context.root;
}

void cjson_cbor_stream_decode(cJSON *source, const struct cbor_callbacks *callbacks, void *context)
{

	switch (source->type) {
	case cJSON_False: {
		callbacks->boolean(context, false);
		return;
	}
	case cJSON_True: {
		callbacks->boolean(context, true);
		return;
	}
	case cJSON_NULL: {
		callbacks->null(context);
		return;
	}
	case cJSON_Number: {
		// This is stupid -- ints and doubles cannot are not distinguished
		if (fabs(source->valuedouble - source->valueint) > DBL_EPSILON) {
			callbacks->float4(context, source->valuedouble);
		} else {
			// XXX: This is not portable
			if (source->valueint >= 0) {
				if (source->valueint < (1 << 8)) {
					callbacks->uint8(context, source->valueint);
				} else if (source->valueint < (1 << 16)) {
					callbacks->uint16(context, source->valueint);
				} else if (source->valueint < (1UL << 32)) {
					callbacks->uint32(context, source->valueint);
				} else {
					callbacks->uint64(context, source->valueint);
				}
			} else {
				callbacks->negint64(context, source->valueint + 1);
			}
		}
		return;
	}
	case cJSON_String: {
		// XXX: Assume cJSON handled unicode correctly
		callbacks->string(context, (unsigned char *)source->valuestring, strlen(source->valuestring));
		return;
	}
	case cJSON_Raw: {
		// XXX: Assume cJSON handled unicode correctly
		int byte_size = strlen(source->valuestring) / 2;
		int i;
		uint8_t *byte_data = (uint8_t *)malloc(byte_size);
		for (i = 0; i < byte_size; ++i) {
			byte_data[i] = 16 * toInt(source->valuestring[2 * i]) + toInt(source->valuestring[2 * i + 1]);
		}
		callbacks->byte_string(context, (unsigned char *)byte_data, byte_size);
		free(byte_data);
		return;
	}
	case cJSON_Array: {
		callbacks->array_start(context, cJSON_GetArraySize(source));
		cJSON *item = source->child;
		while (item != NULL) {
			cjson_cbor_stream_decode(item, callbacks, context);
			item = item->next;
		}
		return;
	}
	case cJSON_Object: {
		bool flag = false;
		callbacks->map_start(context, cJSON_GetArraySize(source));
		cJSON *item;

		if (source->string != NULL && ((strncmp("privatedata", source->string, strlen(source->string)) == 0)
									   || (strncmp("publicdata", source->string, strlen(source->string)) == 0)
									   || (strncmp("optionaldata", source->string, strlen(source->string)) == 0))) {
			item = source->child;
			while (item != NULL) {
				if (item->string != NULL) {
					if (strncmp("encoding", item->string, strlen(item->string)) == 0) {
						if ((strncmp("oic.sec.encoding.raw", item->valuestring, strlen(item->valuestring)) == 0)
							|| (strncmp("oic.sec.encoding.der", item->valuestring, strlen(item->valuestring)) == 0)) {
							flag = true;
						}
					}
				}
				item = item->next;
			}
		}

		item = source->child;
		while (item != NULL) {
			if (flag == true && (strncmp("data", item->string, strlen(item->string)) == 0)) {
				item->type = cJSON_Raw;
			}
			callbacks->string(context, (unsigned char *)item->string, strlen(item->string));
			cjson_cbor_stream_decode(item, callbacks, context);
			item = item->next;
		}
		return;
	}
	}
}

void usage()
{
	printf("Usage: cjson [input JSON file]\n");
	exit(1);
}

int main(int argc, char *argv[])
{
	if (argc != 2) {
		usage();
	}
	FILE *f = fopen(argv[1], "rb");
	if (f == NULL) {
		usage();
	}
	/* Read input file into a buffer (cJSON doesn't work with streams) */
	fseek(f, 0, SEEK_END);
	size_t length = (size_t) ftell(f);
	fseek(f, 0, SEEK_SET);
	char *json_buffer = malloc(length + 1);
	fread(json_buffer, length, 1, f);
	json_buffer[length] = '\0';

	/* Convert between JSON and CBOR */
	cJSON *json = cJSON_Parse(json_buffer);
	cbor_item_t *cbor = cjson_cbor_load(json, cjson_cbor_stream_decode);

	/* Print out CBOR bytes */
	unsigned char *buffer;
	size_t buffer_size, cbor_length = cbor_serialize_alloc(cbor, &buffer, &buffer_size);

	fwrite(buffer, 1, cbor_length, stdout);

	free(buffer);
	fflush(stdout);
	cJSON_Delete(json);
	cbor_decref(&cbor);
}
