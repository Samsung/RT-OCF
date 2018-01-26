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

#ifndef __RT_OCF_REP_H
#define __RT_OCF_REP_H

#include "cbor.h"
#include "ocf_rep.h"

#define MAX_ITEM_COUNT 0xFFU	// 255

typedef struct _key_node {
	char *key;
	struct _key_node *next;
} key_node_s;

typedef struct _rt_rep_encoder_s {
	CborEncoder root;
	CborEncoder encoder;
	ocf_rep_type_t type;
	key_node_s *key_list;
	uint8_t count;
	uint8_t *payload;
	size_t buffer_size;
	size_t payload_size;
} rt_rep_encoder_s;

typedef struct _rt_rep_decoder_s {
	CborValue root_value;
	ocf_rep_type_t type;
	const uint8_t *payload;
} rt_rep_decoder_s;

// Encoder
rt_rep_encoder_s *rt_rep_encoder_init(ocf_rep_type_t type);
rt_rep_encoder_s *rt_rep_encoder_init_with_buffer_size(ocf_rep_type_t type, size_t buffer_size);
void rt_rep_encoder_release(rt_rep_encoder_s *rep);

// Add - Map
ocf_result_t rt_rep_add_bool_to_map(rt_rep_encoder_s *rep, const char *key, bool value);
ocf_result_t rt_rep_add_int_to_map(rt_rep_encoder_s *rep, const char *key, int value);
ocf_result_t rt_rep_add_double_to_map(rt_rep_encoder_s *rep, const char *key, double value);
ocf_result_t rt_rep_add_string_to_map(rt_rep_encoder_s *rep, const char *key, const char *string);
ocf_result_t rt_rep_add_byte_to_map(rt_rep_encoder_s *rep, const char *key, const uint8_t *value, size_t length);
ocf_result_t rt_rep_add_map_to_map(rt_rep_encoder_s *rep, const char *key, rt_rep_encoder_s *sub);
ocf_result_t rt_rep_add_array_to_map(rt_rep_encoder_s *rep, const char *key, rt_rep_encoder_s *sub);

// Add - Array
ocf_result_t rt_rep_add_bool_to_array(rt_rep_encoder_s *rep, bool value);
ocf_result_t rt_rep_add_int_to_array(rt_rep_encoder_s *rep, int value);
ocf_result_t rt_rep_add_double_to_array(rt_rep_encoder_s *rep, double value);
ocf_result_t rt_rep_add_string_to_array(rt_rep_encoder_s *rep, const char *string);
ocf_result_t rt_rep_add_byte_to_array(rt_rep_encoder_s *rep, const uint8_t *value, size_t length);
ocf_result_t rt_rep_add_map_to_array(rt_rep_encoder_s *rep, rt_rep_encoder_s *sub);
ocf_result_t rt_rep_add_array_to_array(rt_rep_encoder_s *rep, rt_rep_encoder_s *sub);

// Decoder
rt_rep_decoder_s *rt_rep_decoder_init(const uint8_t *payload, uint16_t size);
void rt_rep_decoder_release(rt_rep_decoder_s *rep);

// Get - Map
ocf_result_t rt_rep_get_bool_from_map(rt_rep_decoder_s *rep, const char *key, bool *value);
ocf_result_t rt_rep_get_int_from_map(rt_rep_decoder_s *rep, const char *key, int *value);
ocf_result_t rt_rep_get_double_from_map(rt_rep_decoder_s *rep, const char *key, double *value);
ocf_result_t rt_rep_get_string_from_map(rt_rep_decoder_s *rep, const char *key, char *value);
ocf_result_t rt_rep_get_string_length_from_map(rt_rep_decoder_s *rep, const char *key, size_t *len);
ocf_result_t rt_rep_get_byte_from_map(rt_rep_decoder_s *rep, const char *key, uint8_t *value);
#define rt_rep_get_byte_length_from_map(rep, key, len) rt_rep_get_string_length_from_map(rep, key, len);
ocf_result_t rt_rep_get_map_from_map(rt_rep_decoder_s *rep, const char *key, rt_rep_decoder_s *sub);
ocf_result_t rt_rep_get_array_from_map(rt_rep_decoder_s *rep, const char *key, rt_rep_decoder_s *sub);

// Get - Array
ocf_result_t rt_rep_get_array_length(const rt_rep_decoder_s *rep, uint16_t *size);

ocf_result_t rt_rep_get_bool_from_array(const rt_rep_decoder_s *rep, uint16_t index, bool *value);
ocf_result_t rt_rep_get_int_from_array(const rt_rep_decoder_s *rep, uint16_t index, int *value);
ocf_result_t rt_rep_get_double_from_array(const rt_rep_decoder_s *rep, uint16_t index, double *value);
ocf_result_t rt_rep_get_string_from_array(const rt_rep_decoder_s *rep, uint16_t index, char *value);
ocf_result_t rt_rep_get_string_length_from_array(const rt_rep_decoder_s *rep, uint16_t index, size_t *len);
ocf_result_t rt_rep_get_byte_from_array(const rt_rep_decoder_s *rep, uint16_t index, uint8_t *value);
#define rt_rep_get_byte_length_from_array(rep, index, len) rt_rep_get_string_length_from_array(rep, index, len);
ocf_result_t rt_rep_get_map_from_array(const rt_rep_decoder_s *rep, uint16_t index, rt_rep_decoder_s *sub);
ocf_result_t rt_rep_get_array_from_array(const rt_rep_decoder_s *rep, uint16_t index, rt_rep_decoder_s *sub);

ocf_result_t rt_rep_get_bool_array(const rt_rep_decoder_s *rep, uint16_t size, bool *value);
ocf_result_t rt_rep_get_int_array(const rt_rep_decoder_s *rep, uint16_t size, int *value);
ocf_result_t rt_rep_get_double_array(const rt_rep_decoder_s *rep, uint16_t size, double *value);
ocf_result_t rt_rep_get_string_array(const rt_rep_decoder_s *rep, uint16_t size, char **value);
ocf_result_t rt_rep_get_byte_array(const rt_rep_decoder_s *rep, uint16_t size, uint8_t **value);
ocf_result_t rt_rep_get_map_array(const rt_rep_decoder_s *rep, uint16_t size, rt_rep_decoder_s *sub);
ocf_result_t rt_rep_get_array_array(const rt_rep_decoder_s *rep, uint16_t size, rt_rep_decoder_s *sub);

void rt_rep_encoder_log(const rt_rep_encoder_s *rep);
void rt_rep_decoder_log(const rt_rep_decoder_s *rep, uint8_t indent);

#endif							/* __RT_OCF_REP_H */
