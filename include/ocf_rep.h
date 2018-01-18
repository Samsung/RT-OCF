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

#ifndef OCFREP_H_
#define OCFREP_H_

#include "ocf_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct rt_rep_encoder_s *ocf_rep_encoder_s;
typedef struct rt_rep_decoder_s *ocf_rep_decoder_s;

typedef enum {
	OCF_REP_MAP,
	OCF_REP_ARRAY
} ocf_rep_type_t;

ocf_rep_encoder_s ocf_rep_encoder_init(ocf_rep_type_t type);
void ocf_rep_encoder_release(ocf_rep_encoder_s rep);

// Add - Map
ocf_result_t ocf_rep_add_bool_to_map(ocf_rep_encoder_s rep, const char *key, bool value);
ocf_result_t ocf_rep_add_int_to_map(ocf_rep_encoder_s rep, const char *key, int value);
ocf_result_t ocf_rep_add_double_to_map(ocf_rep_encoder_s rep, const char *key, double value);
ocf_result_t ocf_rep_add_string_to_map(ocf_rep_encoder_s rep, const char *key, const char *string);
ocf_result_t ocf_rep_add_byte_to_map(ocf_rep_encoder_s rep, const char *key, const uint8_t *value, size_t length);
ocf_result_t ocf_rep_add_map_to_map(ocf_rep_encoder_s rep, const char *key, ocf_rep_encoder_s sub);
ocf_result_t ocf_rep_add_array_to_map(ocf_rep_encoder_s rep, const char *key, ocf_rep_encoder_s sub);

// Add - Array
ocf_result_t ocf_rep_add_bool_to_array(ocf_rep_encoder_s rep, bool value);
ocf_result_t ocf_rep_add_int_to_array(ocf_rep_encoder_s rep, int value);
ocf_result_t ocf_rep_add_double_to_array(ocf_rep_encoder_s rep, double value);
ocf_result_t ocf_rep_add_string_to_array(ocf_rep_encoder_s rep, const char *string);
ocf_result_t ocf_rep_add_byte_to_array(ocf_rep_encoder_s rep, const uint8_t *value, size_t length);
ocf_result_t ocf_rep_add_map_to_array(ocf_rep_encoder_s rep, ocf_rep_encoder_s sub);
ocf_result_t ocf_rep_add_array_to_array(ocf_rep_encoder_s rep, ocf_rep_encoder_s sub);

// Decoder
ocf_rep_decoder_s ocf_rep_decoder_init(const uint8_t *payload, uint16_t size);
void ocf_rep_decoder_release(ocf_rep_decoder_s rep);

uint8_t *ocf_rep_decoder_get_payload_addr(ocf_rep_encoder_s rep);
size_t ocf_rep_decoder_get_payload_size(ocf_rep_encoder_s rep);

// Get - Map
ocf_result_t ocf_rep_get_bool_from_map(ocf_rep_decoder_s rep, const char *key, bool *value);
ocf_result_t ocf_rep_get_int_from_map(ocf_rep_decoder_s rep, const char *key, int *value);
ocf_result_t ocf_rep_get_double_from_map(ocf_rep_decoder_s rep, const char *key, double *value);
ocf_result_t ocf_rep_get_string_from_map(ocf_rep_decoder_s rep, const char *key, char *value);
ocf_result_t ocf_rep_get_string_length_from_map(ocf_rep_decoder_s rep, const char *key, size_t *len);
ocf_result_t ocf_rep_get_byte_from_map(ocf_rep_decoder_s rep, const char *key, uint8_t *value);
ocf_result_t ocf_rep_get_byte_length_from_map(ocf_rep_decoder_s rep, const char *key, size_t *len);
ocf_result_t ocf_rep_get_map_from_map(ocf_rep_decoder_s rep, const char *key, ocf_rep_decoder_s sub);
ocf_result_t ocf_rep_get_array_from_map(ocf_rep_decoder_s rep, const char *key, ocf_rep_decoder_s sub);

// Get - Array
ocf_result_t ocf_rep_get_array_length(const ocf_rep_decoder_s rep, uint16_t *size);

ocf_result_t ocf_rep_get_bool_from_array(const ocf_rep_decoder_s rep, uint16_t index, bool *value);
ocf_result_t ocf_rep_get_int_from_array(const ocf_rep_decoder_s rep, uint16_t index, int *value);
ocf_result_t ocf_rep_get_double_from_array(const ocf_rep_decoder_s rep, uint16_t index, double *value);
ocf_result_t ocf_rep_get_string_from_array(const ocf_rep_decoder_s rep, uint16_t index, char *value);
ocf_result_t ocf_rep_get_string_length_from_array(const ocf_rep_decoder_s rep, uint16_t index, size_t *len);
ocf_result_t ocf_rep_get_byte_from_array(const ocf_rep_decoder_s rep, uint16_t index, uint8_t *value);
ocf_result_t ocf_rep_get_byte_length_from_array(const ocf_rep_decoder_s rep, uint16_t index, size_t *len);
ocf_result_t ocf_rep_get_map_from_array(const ocf_rep_decoder_s rep, uint16_t index, ocf_rep_decoder_s sub);
ocf_result_t ocf_rep_get_array_from_array(const ocf_rep_decoder_s rep, uint16_t index, ocf_rep_decoder_s sub);

ocf_result_t ocf_rep_get_bool_array(const ocf_rep_decoder_s rep, uint16_t size, bool *value);
ocf_result_t ocf_rep_get_int_array(const ocf_rep_decoder_s rep, uint16_t size, int *value);
ocf_result_t ocf_rep_get_double_array(const ocf_rep_decoder_s rep, uint16_t size, double *value);
ocf_result_t ocf_rep_get_string_array(const ocf_rep_decoder_s rep, uint16_t size, char **value);
ocf_result_t ocf_rep_get_byte_array(const ocf_rep_decoder_s rep, uint16_t size, uint8_t **value);
ocf_result_t ocf_rep_get_map_array(const ocf_rep_decoder_s rep, uint16_t size, ocf_rep_decoder_s sub);
ocf_result_t ocf_rep_get_array_array(const ocf_rep_decoder_s rep, uint16_t size, ocf_rep_decoder_s sub);

#ifdef __cplusplus
}
#endif							// __cplusplus
#endif
