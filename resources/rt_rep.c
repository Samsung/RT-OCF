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

#include <string.h>
#include "rt_rep.h"
#include "rt_mem.h"
#include "rt_utils.h"
#include "rt_string.h"

#define TAG "RT_REP"

#define EMPTY_CONTAINER_SIZE 2
#define DEFAULT_REP_SIZE 255

static ocf_result_t rt_rep_create_container(rt_rep_encoder_s *rep, ocf_rep_type_t type)
{
	CborError err = CborNoError;
	rep->type = type;
	rep->key_list = NULL;
	rep->count = 0;
	if (OCF_REP_MAP == type) {
		err |= cbor_encoder_create_map(&rep->root, &rep->encoder, CborIndefiniteLength);
	} else if (OCF_REP_ARRAY == type) {
		err |= cbor_encoder_create_array(&rep->root, &rep->encoder, CborIndefiniteLength);
	} else {
		RT_LOG_E(TAG, "invaild container type");
		return OCF_ERROR;
	}
	err |= cbor_encoder_close_container(&rep->root, &rep->encoder);

	if (err != CborNoError) {
		return OCF_ERROR;
	}

	return OCF_OK;
}

rt_rep_encoder_s *rt_rep_encoder_init(ocf_rep_type_t type)
{
	return rt_rep_encoder_init_with_buffer_size(type, DEFAULT_REP_SIZE);
}

rt_rep_encoder_s *rt_rep_encoder_init_with_buffer_size(ocf_rep_type_t type, size_t buffer_size)
{
	if (buffer_size <= 0) {
		RT_LOG_E(TAG, "size should bigger than 0.");
		return NULL;
	}

	rt_rep_encoder_s *rep = (rt_rep_encoder_s *) rt_mem_alloc(sizeof(rt_rep_encoder_s));
	RT_VERIFY_NON_NULL_RET(rep, TAG, "rep memory alloc failed!", NULL);

	rep->payload = (uint8_t *) rt_mem_alloc(buffer_size);
	if (!(rep->payload)) {
		RT_LOG_E(TAG, "payload memory alloc failed!");
		rt_mem_free(rep);
		return NULL;
	}
	rep->buffer_size = buffer_size;
	rep->payload_size = EMPTY_CONTAINER_SIZE;

	cbor_encoder_init(&rep->root, rep->payload, rep->buffer_size, 0);

	ocf_result_t ret = rt_rep_create_container(rep, type);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "encoder init failed!");
		rt_mem_free(rep->payload);
		rt_mem_free(rep);

		return NULL;
	}

	return rep;
}

void rt_rep_encoder_release(rt_rep_encoder_s *rep)
{
	RT_VERIFY_NON_NULL_VOID(rep, TAG, "encoder rep is NULL");

	key_node_s *itr = rep->key_list;
	while (itr) {
		key_node_s *temp = itr;
		itr = itr->next;
		rt_mem_free(temp->key);
		rt_mem_free(temp);
	}

	if (rep->payload != NULL) {
		rt_mem_free(rep->payload);
	}
	rt_mem_free(rep);
}

static ocf_result_t rt_rep_check_buffer_and_expand_if_needed(rt_rep_encoder_s *rep, CborError err)
{
	if (CborErrorOutOfMemory == err) {
		size_t extra_size = cbor_encoder_get_extra_bytes_needed(&rep->encoder);
		if (extra_size < DEFAULT_REP_SIZE) {
			extra_size = DEFAULT_REP_SIZE;
		}

		rep->buffer_size += extra_size;
		rep->payload = rt_mem_realloc(rep->payload, rep->buffer_size);
		RT_VERIFY_NON_NULL_RET(rep->payload, TAG, "rep->payload realloc failed", OCF_MEM_FULL);

		cbor_encoder_reinit(&rep->root, rep->payload, rep->payload_size, rep->buffer_size);
		cbor_encoder_reinit(&rep->encoder, rep->payload, rep->payload_size - 1, rep->buffer_size);

		return OCF_ERROR;
	}

	return OCF_OK;
}

static void rt_rep_insert_key(rt_rep_encoder_s *rep, const char *key)
{
	key_node_s *key_node = (key_node_s *) rt_mem_alloc(sizeof(key_node_s));
	RT_VERIFY_NON_NULL_VOID(key_node, TAG, "key_node memory alloc failed!");

	key_node->key = (char *)rt_mem_alloc(strlen(key) + 1);
	if (!key_node->key) {
		RT_LOG_E(TAG, "key memory alloc failed!");
		rt_mem_free(key_node);
		return;
	}

	rt_strcpy(key_node->key, key);
	key_node->next = rep->key_list;
	rep->key_list = key_node;
}

static ocf_result_t rt_rep_setup(rt_rep_encoder_s *rep, ocf_rep_type_t type, const char *key)
{
	RT_VERIFY_NON_NULL(rep, TAG, "rep");
	if (MAX_ITEM_COUNT <= rep->count) {
		RT_LOG_E(TAG, "Item slot is full");
		return OCF_ERROR;
	}
	if (OCF_REP_MAP == type) {
		RT_VERIFY_NON_NULL(key, TAG, "key");

		key_node_s *itr = rep->key_list;
		while (itr) {
			if (strcmp(itr->key, key) == 0) {
				return OCF_ERROR;
			}
			itr = itr->next;
		}
	}

	if (rep->type != type) {
		return OCF_ERROR;
	}

	return OCF_OK;
}

static ocf_result_t rt_rep_teardown(rt_rep_encoder_s *rep, const char *key, CborError err)
{
	RT_VERIFY_NON_NULL(rep, TAG, "rep");

	if (err != CborNoError) {
		return OCF_ERROR;
	}

	if (OCF_REP_MAP == rep->type) {
		RT_VERIFY_NON_NULL(key, TAG, "key");
		rt_rep_insert_key(rep, key);
	}
	rep->count++;
	rep->payload_size = cbor_encoder_get_buffer_size(&rep->root, rep->payload);

	return OCF_OK;
}

static CborError rt_rep_encode_value(rt_rep_encoder_s *rep, CborType type, const void *value, size_t length)
{
	CborError err = CborNoError;
	switch (type) {
	case CborBooleanType:
		err = cbor_encode_boolean(&rep->encoder, *(bool *)(value));
		break;
	case CborIntegerType:
		err = cbor_encode_int(&rep->encoder, *(int *)(value));
		break;
	case CborDoubleType:
		err = cbor_encode_double(&rep->encoder, *(double *)(value));
		break;
	case CborTextStringType:
		err = cbor_encode_text_string(&rep->encoder, (const char *)value, strlen(value));
		break;
	case CborByteStringType:
		err = cbor_encode_byte_string(&rep->encoder, (const uint8_t *)value, length);
		break;
	case CborMapType: {
		rt_rep_encoder_s *sub = (rt_rep_encoder_s *) value;
		err = cbor_encode_map(&rep->encoder, sub->payload, sub->payload_size, sub->count);
		break;
	}
	case CborArrayType: {
		rt_rep_encoder_s *sub = (rt_rep_encoder_s *) value;
		err = cbor_encode_array(&rep->encoder, sub->payload, sub->payload_size, sub->count);
		break;
	}
	default:
		RT_LOG_E(TAG, "%d type not handled.", type);
		err = CborErrorInternalError;
		break;
	}

	return err;
}

static ocf_result_t rt_rep_add_value_to_map(rt_rep_encoder_s *rep, CborType type, const char *key, const void *value, size_t length)
{
	ocf_result_t ret = rt_rep_setup(rep, OCF_REP_MAP, key);
	if (OCF_OK != ret) {
		return ret;
	}

	CborError err = CborNoError;
	do {
		err = cbor_encode_text_string(&rep->encoder, key, strlen(key));
		err |= rt_rep_encode_value(rep, type, value, length);
		err |= cbor_encoder_close_container(&rep->root, &rep->encoder);
	} while (OCF_ERROR == rt_rep_check_buffer_and_expand_if_needed(rep, err));

	return rt_rep_teardown(rep, key, err);
}

ocf_result_t rt_rep_add_bool_to_map(rt_rep_encoder_s *rep, const char *key, bool value)
{
	return rt_rep_add_value_to_map(rep, CborBooleanType, key, &value, 0);
}

ocf_result_t rt_rep_add_int_to_map(rt_rep_encoder_s *rep, const char *key, int value)
{
	return rt_rep_add_value_to_map(rep, CborIntegerType, key, &value, 0);
}

ocf_result_t rt_rep_add_double_to_map(rt_rep_encoder_s *rep, const char *key, double value)
{
	return rt_rep_add_value_to_map(rep, CborDoubleType, key, &value, 0);
}

ocf_result_t rt_rep_add_string_to_map(rt_rep_encoder_s *rep, const char *key, const char *value)
{
	RT_VERIFY_NON_NULL(value, TAG, "value");
	return rt_rep_add_value_to_map(rep, CborTextStringType, key, value, 0);
}

ocf_result_t rt_rep_add_byte_to_map(rt_rep_encoder_s *rep, const char *key, const uint8_t *value, size_t length)
{
	RT_VERIFY_NON_NULL(value, TAG, "value");
	return rt_rep_add_value_to_map(rep, CborByteStringType, key, value, length);
}

ocf_result_t rt_rep_add_map_to_map(rt_rep_encoder_s *rep, const char *key, rt_rep_encoder_s *sub)
{
	RT_VERIFY_NON_NULL(sub, TAG, "sub");

	if (OCF_REP_MAP != sub->type) {
		RT_LOG_E(TAG, "invaild type");
		return OCF_ERROR;
	}

	return rt_rep_add_value_to_map(rep, CborMapType, key, sub, 0);
}

ocf_result_t rt_rep_add_array_to_map(rt_rep_encoder_s *rep, const char *key, rt_rep_encoder_s *sub)
{
	RT_VERIFY_NON_NULL(sub, TAG, "sub");

	if (OCF_REP_ARRAY != sub->type) {
		RT_LOG_E(TAG, "invaild type");
		return OCF_ERROR;
	}

	return rt_rep_add_value_to_map(rep, CborArrayType, key, sub, 0);
}

static ocf_result_t rt_rep_add_value_to_array(rt_rep_encoder_s *rep, CborType type, const void *value, size_t length)
{
	ocf_result_t ret = rt_rep_setup(rep, OCF_REP_ARRAY, NULL);
	if (OCF_OK != ret) {
		return ret;
	}

	CborError err = CborNoError;
	do {
		err = rt_rep_encode_value(rep, type, value, length);
		err |= cbor_encoder_close_container(&rep->root, &rep->encoder);
	} while (OCF_ERROR == rt_rep_check_buffer_and_expand_if_needed(rep, err));

	return rt_rep_teardown(rep, NULL, err);
}

ocf_result_t rt_rep_add_bool_to_array(rt_rep_encoder_s *rep, bool value)
{
	return rt_rep_add_value_to_array(rep, CborBooleanType, &value, 0);
}

ocf_result_t rt_rep_add_int_to_array(rt_rep_encoder_s *rep, int value)
{
	return rt_rep_add_value_to_array(rep, CborIntegerType, &value, 0);
}

ocf_result_t rt_rep_add_double_to_array(rt_rep_encoder_s *rep, double value)
{
	return rt_rep_add_value_to_array(rep, CborDoubleType, &value, 0);
}

ocf_result_t rt_rep_add_string_to_array(rt_rep_encoder_s *rep, const char *value)
{
	RT_VERIFY_NON_NULL(value, TAG, "value");

	return rt_rep_add_value_to_array(rep, CborTextStringType, value, 0);
}

ocf_result_t rt_rep_add_byte_to_array(rt_rep_encoder_s *rep, const uint8_t *value, size_t length)
{
	RT_VERIFY_NON_NULL(value, TAG, "value");

	return rt_rep_add_value_to_array(rep, CborByteStringType, value, length);
}

ocf_result_t rt_rep_add_map_to_array(rt_rep_encoder_s *rep, rt_rep_encoder_s *sub)
{
	RT_VERIFY_NON_NULL(sub, TAG, "sub");

	if (OCF_REP_MAP != sub->type) {
		RT_LOG_E(TAG, "invaild type");
		return OCF_ERROR;
	}

	return rt_rep_add_value_to_array(rep, CborMapType, sub, 0);
}

ocf_result_t rt_rep_add_array_to_array(rt_rep_encoder_s *rep, rt_rep_encoder_s *sub)
{
	RT_VERIFY_NON_NULL(sub, TAG, "sub");

	if (OCF_REP_ARRAY != sub->type) {
		RT_LOG_E(TAG, "invaild type");
		return OCF_ERROR;
	}

	return rt_rep_add_value_to_array(rep, CborArrayType, sub, 0);
}

// Get
rt_rep_decoder_s *rt_rep_decoder_init(const uint8_t *payload, uint16_t size)
{
	RT_VERIFY_NON_NULL_RET(payload, TAG, "payload is null!", NULL);
	if (size <= 0) {
		RT_LOG_E(TAG, "size should bigger than 0.");
		return NULL;
	}

	rt_rep_decoder_s *rep = (rt_rep_decoder_s *) rt_mem_alloc(sizeof(rt_rep_decoder_s));
	RT_VERIFY_NON_NULL_RET(rep, TAG, "rep memory alloc failed!", NULL);

	rep->payload = (uint8_t *) rt_mem_dup(payload, size);
	if (!rep->payload) {
		RT_LOG_E(TAG, "payload init failed");
		rt_mem_free(rep);
		return NULL;
	}

	CborParser parser;
	CborError err = cbor_parser_init(rep->payload, size, 0, &parser, &rep->root_value);
	if (err != CborNoError) {
		RT_LOG_E(TAG, "parser init failed");
		rt_rep_decoder_release(rep);
		return NULL;
	}
	rep->type = cbor_value_is_map(&rep->root_value) ? OCF_REP_MAP : OCF_REP_ARRAY;

	return rep;
}

void rt_rep_decoder_release(rt_rep_decoder_s *rep)
{
	RT_VERIFY_NON_NULL_VOID(rep, TAG, "decoder rep is NULL");

	rt_mem_free((uint8_t *) rep->payload);
	rt_mem_free(rep);
}

static CborError rt_rep_get_cbor_value(const CborValue *cbor_value, void *value, int index)
{
	CborError err = CborNoError;
	switch (cbor_value->type) {
	case CborBooleanType:
		err = cbor_value_get_boolean(cbor_value, &((bool *) value)[index]);
		break;
	case CborIntegerType:
		err = cbor_value_get_int(cbor_value, &((int *)value)[index]);
		break;
	case CborDoubleType:
		err = cbor_value_get_double(cbor_value, &((double *)value)[index]);
		break;
	case CborTextStringType: {
		size_t len;
		err = cbor_value_get_string_length(cbor_value, &len);
		len++;
		err |= cbor_value_copy_text_string(cbor_value, ((char **)value)[index], &len, NULL);
		break;
	}
	case CborByteStringType: {
		size_t len;
		err = cbor_value_get_string_length(cbor_value, &len);
		err |= cbor_value_copy_byte_string(cbor_value, ((uint8_t **) value)[index], &len, NULL);
		break;
	}
	case CborMapType:
	case CborArrayType:
		((rt_rep_decoder_s *) value)[index].root_value = *cbor_value;
		((rt_rep_decoder_s *) value)[index].type = (cbor_value->type == CborMapType) ? OCF_REP_MAP : OCF_REP_ARRAY;;
		break;
	}

	return err;
}

static ocf_result_t rt_rep_get_value_from_map(rt_rep_decoder_s *rep, CborType type, const char *key, void *value)
{
	RT_VERIFY_NON_NULL(rep, TAG, "rep");
	RT_VERIFY_NON_NULL(key, TAG, "key");
	RT_VERIFY_NON_NULL(value, TAG, "value");

	if (OCF_REP_MAP != rep->type) {
		RT_LOG_E(TAG, "Invaild container type");
		return OCF_ERROR;
	}

	CborValue cbor_value;
	CborError err = CborNoError;
	err = cbor_value_map_find_value(&rep->root_value, key, &cbor_value);
	if (err != CborNoError) {
		RT_LOG_W(TAG, "Can not find the key:%s", key);
		return OCF_INVALID_PARAM;
	}

	if (cbor_value.type != type) {
		RT_LOG_E(TAG, "Invaild value type");
		return OCF_ERROR;
	}

	err |= rt_rep_get_cbor_value(&cbor_value, value, 0);

	if (err != CborNoError) {
		return OCF_ERROR;
	}

	return OCF_OK;
}

ocf_result_t rt_rep_get_bool_from_map(rt_rep_decoder_s *rep, const char *key, bool *value)
{
	return rt_rep_get_value_from_map(rep, CborBooleanType, key, value);
}

ocf_result_t rt_rep_get_int_from_map(rt_rep_decoder_s *rep, const char *key, int *value)
{
	return rt_rep_get_value_from_map(rep, CborIntegerType, key, value);
}

ocf_result_t rt_rep_get_double_from_map(rt_rep_decoder_s *rep, const char *key, double *value)
{
	return rt_rep_get_value_from_map(rep, CborDoubleType, key, value);
}

ocf_result_t rt_rep_get_string_from_map(rt_rep_decoder_s *rep, const char *key, char *value)
{
	RT_VERIFY_NON_NULL(value, TAG, "value");
	return rt_rep_get_value_from_map(rep, CborTextStringType, key, &value);
}

ocf_result_t rt_rep_get_string_length_from_map(rt_rep_decoder_s *rep, const char *key, size_t *len)
{
	RT_VERIFY_NON_NULL(rep, TAG, "rep");
	RT_VERIFY_NON_NULL(key, TAG, "key");
	RT_VERIFY_NON_NULL(len, TAG, "len");

	CborValue cbor_value;
	CborError err = CborNoError;
	err = cbor_value_map_find_value(&rep->root_value, key, &cbor_value);
	err |= cbor_value_get_string_length(&cbor_value, len);

	if (err != CborNoError) {
		return OCF_ERROR;
	}

	return OCF_OK;
}

ocf_result_t rt_rep_get_byte_from_map(rt_rep_decoder_s *rep, const char *key, uint8_t *value)
{
	RT_VERIFY_NON_NULL(value, TAG, "value");
	return rt_rep_get_value_from_map(rep, CborByteStringType, key, &value);
}

ocf_result_t rt_rep_get_map_from_map(rt_rep_decoder_s *rep, const char *key, rt_rep_decoder_s *sub)
{
	return rt_rep_get_value_from_map(rep, CborMapType, key, sub);
}

ocf_result_t rt_rep_get_array_from_map(rt_rep_decoder_s *rep, const char *key, rt_rep_decoder_s *sub)
{
	return rt_rep_get_value_from_map(rep, CborArrayType, key, sub);
}

ocf_result_t rt_rep_get_array_length(const rt_rep_decoder_s *rep, uint16_t *size)
{
	RT_VERIFY_NON_NULL(rep, TAG, "rep");
	RT_VERIFY_NON_NULL(size, TAG, "size");

	if (OCF_REP_ARRAY != rep->type) {
		RT_LOG_E(TAG, "Invaild container type");
		return OCF_ERROR;
	}

	CborValue cbor_value;
	cbor_value_enter_container(&rep->root_value, &cbor_value);
	// TODO: Utilize cbor_value_get_array_length() for efficiency
	CborError err = CborNoError;
	*size = 0;
	while (!cbor_value_at_end(&cbor_value)) {
		(*size)++;
		err = cbor_value_advance(&cbor_value);
		if (err != CborNoError) {
			return OCF_ERROR;
		}
	}

	return OCF_OK;
}

static ocf_result_t rt_rep_get_value_from_array(const rt_rep_decoder_s *rep, CborType type, uint16_t index, void *value)
{
	RT_VERIFY_NON_NULL(rep, TAG, "rep");
	RT_VERIFY_NON_NULL(value, TAG, "value");
	if (OCF_REP_ARRAY != rep->type) {
		RT_LOG_E(TAG, "Invaild container type");
		return OCF_ERROR;
	}

	uint16_t array_size = 0;
	ocf_result_t ret = rt_rep_get_array_length(rep, &array_size);
	if (OCF_OK != ret || array_size <= index) {
		RT_LOG_E(TAG, "Invaild array size");
		return OCF_ERROR;
	}

	CborValue cbor_value;
	CborError err = CborNoError;
	err |= cbor_value_enter_container(&rep->root_value, &cbor_value);
	if (cbor_value.type != type) {
		RT_LOG_E(TAG, "Invaild value type");
		return OCF_ERROR;
	}

	while (0 < index--) {
		err |= cbor_value_advance(&cbor_value);
	}

	err |= rt_rep_get_cbor_value(&cbor_value, value, 0);

	if (err != CborNoError) {
		return OCF_ERROR;
	}

	return OCF_OK;
}

static ocf_result_t rt_rep_get_value_array(const rt_rep_decoder_s *rep, CborType type, uint16_t size, void *value)
{
	RT_VERIFY_NON_NULL(rep, TAG, "rep");
	RT_VERIFY_NON_NULL(value, TAG, "value");
	if (OCF_REP_ARRAY != rep->type) {
		RT_LOG_E(TAG, "Invaild container type");
		return OCF_ERROR;
	}

	uint16_t array_size = 0;
	ocf_result_t ret = rt_rep_get_array_length(rep, &array_size);
	if (OCF_OK != ret || array_size != size) {
		RT_LOG_E(TAG, "Invaild array size");
		return OCF_ERROR;
	}

	CborValue cbor_value;
	CborError err = CborNoError;
	err |= cbor_value_enter_container(&rep->root_value, &cbor_value);
	if (cbor_value.type != type) {
		RT_LOG_E(TAG, "Invaild value type");
		return OCF_ERROR;
	}
	int index;
	for (index = 0; index < size; index++) {
		err |= rt_rep_get_cbor_value(&cbor_value, value, index);
		err |= cbor_value_advance(&cbor_value);
	}

	if (err != CborNoError) {
		return OCF_ERROR;
	}

	return OCF_OK;
}

ocf_result_t rt_rep_get_bool_from_array(const rt_rep_decoder_s *rep, uint16_t index, bool *value)
{
	return rt_rep_get_value_from_array(rep, CborBooleanType, index, value);
}

ocf_result_t rt_rep_get_int_from_array(const rt_rep_decoder_s *rep, uint16_t index, int *value)
{
	return rt_rep_get_value_from_array(rep, CborIntegerType, index, value);
}

ocf_result_t rt_rep_get_double_from_array(const rt_rep_decoder_s *rep, uint16_t index, double *value)
{
	return rt_rep_get_value_from_array(rep, CborDoubleType, index, value);
}

ocf_result_t rt_rep_get_string_from_array(const rt_rep_decoder_s *rep, uint16_t index, char *value)
{
	RT_VERIFY_NON_NULL(value, TAG, "value");
	return rt_rep_get_value_from_array(rep, CborTextStringType, index, &value);
}

ocf_result_t rt_rep_get_string_length_from_array(const rt_rep_decoder_s *rep, uint16_t index, size_t *len)
{
	RT_VERIFY_NON_NULL(rep, TAG, "rep");
	RT_VERIFY_NON_NULL(len, TAG, "len");
	if (OCF_REP_ARRAY != rep->type) {
		RT_LOG_E(TAG, "Invaild container type");
		return OCF_ERROR;
	}

	uint16_t array_size = 0;
	ocf_result_t ret = rt_rep_get_array_length(rep, &array_size);
	if (OCF_OK != ret || array_size <= index) {
		RT_LOG_E(TAG, "Invaild array size");
		return OCF_ERROR;
	}

	CborValue cbor_value;
	CborError err = CborNoError;
	err |= cbor_value_enter_container(&rep->root_value, &cbor_value);

	while (0 < index--) {
		err |= cbor_value_advance(&cbor_value);
	}

	err |= cbor_value_get_string_length(&cbor_value, len);

	if (err != CborNoError) {
		return OCF_ERROR;
	}

	return OCF_OK;
}

ocf_result_t rt_rep_get_byte_from_array(const rt_rep_decoder_s *rep, uint16_t index, uint8_t *value)
{
	RT_VERIFY_NON_NULL(value, TAG, "value");
	return rt_rep_get_value_from_array(rep, CborByteStringType, index, &value);
}

ocf_result_t rt_rep_get_map_from_array(const rt_rep_decoder_s *rep, uint16_t index, rt_rep_decoder_s *sub)
{
	return rt_rep_get_value_from_array(rep, CborMapType, index, sub);
}

ocf_result_t rt_rep_get_array_from_array(const rt_rep_decoder_s *rep, uint16_t index, rt_rep_decoder_s *sub)
{
	return rt_rep_get_value_from_array(rep, CborArrayType, index, sub);
}

ocf_result_t rt_rep_get_bool_array(const rt_rep_decoder_s *rep, uint16_t size, bool *value)
{
	return rt_rep_get_value_array(rep, CborBooleanType, size, value);
}

ocf_result_t rt_rep_get_int_array(const rt_rep_decoder_s *rep, uint16_t size, int *value)
{
	return rt_rep_get_value_array(rep, CborIntegerType, size, value);
}

ocf_result_t rt_rep_get_double_array(const rt_rep_decoder_s *rep, uint16_t size, double *value)
{
	return rt_rep_get_value_array(rep, CborDoubleType, size, value);
}

ocf_result_t rt_rep_get_string_array(const rt_rep_decoder_s *rep, uint16_t size, char **value)
{
	return rt_rep_get_value_array(rep, CborTextStringType, size, value);
}

ocf_result_t rt_rep_get_byte_array(const rt_rep_decoder_s *rep, uint16_t size, uint8_t **value)
{
	return rt_rep_get_value_array(rep, CborByteStringType, size, value);
}

ocf_result_t rt_rep_get_map_array(const rt_rep_decoder_s *rep, uint16_t size, rt_rep_decoder_s *sub)
{
	return rt_rep_get_value_array(rep, CborMapType, size, sub);
}

ocf_result_t rt_rep_get_array_array(const rt_rep_decoder_s *rep, uint16_t size, rt_rep_decoder_s *sub)
{
	return rt_rep_get_value_array(rep, CborArrayType, size, sub);
}

void rt_rep_encoder_log(const rt_rep_encoder_s *rep)
{
	RT_VERIFY_NON_NULL_VOID(rep, TAG, "rep");
	rt_rep_decoder_s *decoder_rep = rt_rep_decoder_init(rep->payload, rep->payload_size);
	if (decoder_rep) {
		rt_rep_decoder_log(decoder_rep, 0);
		rt_rep_decoder_release(decoder_rep);
	}
}

#define MAX_REP_INDENT 5
void rt_rep_decoder_log(const rt_rep_decoder_s *rep, uint8_t indent)
{
	RT_VERIFY_NON_NULL_VOID(rep, TAG, "rep");
	indent = (indent < MAX_REP_INDENT) ? indent : MAX_REP_INDENT - 1;

	char bracket[MAX_REP_INDENT][6] = { "%s", " %s", "  %s", "   %s", "    %s" };
	RT_LOG_D(TAG, bracket[indent], cbor_value_is_map(&rep->root_value) ? "{" : "[");

	bool is_key = false;
	CborValue cbor_value;
	CborError err = CborNoError;
	err |= cbor_value_enter_container(&rep->root_value, &cbor_value);
	while (!cbor_value_at_end(&cbor_value)) {
		if (cbor_value_is_map(&rep->root_value)) {
			is_key ^= true;
		}
		switch (cbor_value.type) {
		case CborBooleanType: {
			bool value;
			err |= cbor_value_get_boolean(&cbor_value, &value);
			char value_str[MAX_REP_INDENT][12] = { " bool:%s", "  bool:%s", "   bool:%s", "    bool:%s", "     bool:%s" };
			RT_LOG_D(TAG, value_str[indent], value ? "true" : "false");
			break;
		}
		case CborIntegerType: {
			int value;
			err |= cbor_value_get_int(&cbor_value, &value);
			char value_str[MAX_REP_INDENT][11] = { " int:%d", "  int:%d", "   int:%d", "    int:%d", "     int:%d" };
			RT_LOG_D(TAG, value_str[indent], value);
			break;
		}
		case CborDoubleType: {
			double value;
			err |= cbor_value_get_double(&cbor_value, &value);
			char value_str[MAX_REP_INDENT][14] = { " double:%f", "  double:%f", "   double:%f", "    double:%f", "     double:%f" };
			RT_LOG_D(TAG, value_str[indent], value);
			break;
		}
		case CborTextStringType: {
			size_t len;
			err |= cbor_value_get_string_length(&cbor_value, &len);
			len++;
			char *value = (char *)rt_mem_alloc(len);
			RT_VERIFY_NON_NULL_VOID(value, TAG, "value");
			err |= cbor_value_copy_text_string(&cbor_value, value, &len, NULL);
			if (is_key) {
				char key_str[MAX_REP_INDENT][11] = { " key:%s", "  key:%s", "   key:%s", "    key:%s", "     key:%s" };
				RT_LOG_D(TAG, key_str[indent], value);
			} else {
				char value_str[MAX_REP_INDENT][14] = { " string:%s", "  string:%s", "   string:%s", "    string:%s", "     string:%s" };
				RT_LOG_D(TAG, value_str[indent], value);
			}
			rt_mem_free(value);
			break;
		}
		case CborByteStringType: {
			size_t len;
			err |= cbor_value_get_string_length(&cbor_value, &len);
			uint8_t *value = (uint8_t *) rt_mem_alloc(len);
			RT_VERIFY_NON_NULL_VOID(value, TAG, "value");
			err |= cbor_value_copy_byte_string(&cbor_value, value, &len, NULL);
			char value_str[MAX_REP_INDENT][12] = { " byte:%s", "  byte:%s", "   byte:%s", "    byte:%s", "     byte:%s" };
			RT_LOG_D(TAG, value_str[indent], value);
			rt_mem_free(value);
			break;
		}
		case CborMapType:
		case CborArrayType: {
			rt_rep_decoder_s sub;
			sub.root_value = cbor_value;
			sub.type = (cbor_value.type == CborMapType) ? OCF_REP_MAP : OCF_REP_ARRAY;
			rt_rep_decoder_log(&sub, indent + 1);
			break;
		}
		}
		err |= cbor_value_advance(&cbor_value);
	}

	if (CborNoError != err) {
		RT_LOG_E(TAG, "rep decoder log failed.");
	}

	RT_LOG_D(TAG, bracket[indent], cbor_value_is_map(&rep->root_value) ? "}" : "]");
}
