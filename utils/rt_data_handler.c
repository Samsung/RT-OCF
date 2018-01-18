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

#include "rt_data_handler.h"
#include "rt_coap.h"
#include "rt_mem.h"
#include "rt_logger.h"
#include "rt_utils.h"
#include "rt_string.h"

#define TAG "RT_DATA_HANDLER"

ocf_result_t rt_data_clone(rt_data_s *dst, const rt_data_s *src)
{
	RT_VERIFY_NON_NULL_RET(dst, TAG, "dst", OCF_INVALID_PARAM);
	RT_VERIFY_NON_NULL_RET(src, TAG, "src", OCF_INVALID_PARAM);
	RT_VERIFY_NON_NULL_RET(src->token.token, TAG, "src->token", OCF_INVALID_PARAM);
	RT_VERIFY_NON_NULL_RET(src->uri_path, TAG, "src->uri_path", OCF_INVALID_PARAM);
	RT_VERIFY_NON_NULL_RET(src->payload, TAG, "src->payload", OCF_INVALID_PARAM);

	dst->flags = src->flags;
	dst->type = src->type;
	dst->code = src->code;

	dst->observe_num = src->observe_num;
	dst->accept = src->accept;
	dst->content_format = src->content_format;

	dst->mid = src->mid;
	
	rt_coap_copy_token(&dst->token, &src->token);

	dst->uri_path = (char *)rt_mem_dup(src->uri_path, strlen(src->uri_path) + 1);
	if (src->query) {
		dst->query = (char *)rt_mem_dup(src->query, strlen(src->query) + 1);
	}
	dst->payload = (uint8_t *) rt_mem_dup(src->payload, src->payload_len);
	dst->payload_len = src->payload_len;

	return OCF_OK;
}

rt_data_s *rt_receive_data_make_item_without_payload(void *coap_data)
{
	RT_VERIFY_NON_NULL_RET(coap_data, TAG, "coap_data", NULL);

	coap_packet_t *coap_pkt = (coap_packet_t *) coap_data;

	rt_data_s *data = (rt_data_s *) rt_mem_alloc(sizeof(rt_data_s));
	RT_VERIFY_NON_NULL_RET(data, TAG, "data", NULL);
	data->flags = 0;

	if (IS_OCF_OPTION(coap_pkt, COAP_OPTION_OCF_ACCEPT)) {
		data->accept = coap_pkt->ocf_accept;
	} else if (IS_OPTION(coap_pkt, COAP_OPTION_ACCEPT)) {
		data->accept = coap_pkt->accept == APPLICATION_VND_OCF_CBOR ? OCF_1_0_0 : OIC_1_1_0;
	} else {
		data->accept = 0;
	}

	if (IS_OCF_OPTION(coap_pkt, COAP_OPTION_OCF_CONTENT_FORMAT)) {
		data->content_format = coap_pkt->ocf_content_format;
	} else if (IS_OPTION(coap_pkt, COAP_OPTION_CONTENT_FORMAT)) {
		data->content_format = coap_pkt->content_format == APPLICATION_VND_OCF_CBOR ? OCF_1_0_0 : OIC_1_1_0;
	} else {
		data->content_format = 0;
	}

	data->type = coap_pkt->type;
	data->code = coap_pkt->code;
	data->mid = coap_pkt->mid;

	if (coap_pkt->token.len > 0) {
		if (TOKEN_LEN != coap_pkt->token.len) {	//TODO token should be same with TOKEN_LEN(4)??
			RT_LOG_E(TAG, "token length is %d.", coap_pkt->token.len);
		}
		rt_coap_copy_token(&data->token, &coap_pkt->token);		
	}

	if (rt_coap_get_header_observe(coap_pkt, &data->observe_num)) {
		data->flags |= RT_OPTION_OBSERVE;
	}

	data->uri_path = NULL;
	char *temp_uri_path = NULL;
	if (coap_pkt->uri_path && coap_pkt->uri_path_len > 0) {
		temp_uri_path = rt_mem_alloc(sizeof(char) * (coap_pkt->uri_path_len + 2));
		if (!temp_uri_path) {
			RT_LOG_E(TAG, "temp_uri_path alloc failed!");
			rt_data_free_item(data);
			return NULL;
		}
		rt_strcpy(temp_uri_path, "/");
		rt_strncpy(temp_uri_path + 1, coap_pkt->uri_path, coap_pkt->uri_path_len);
		data->uri_path = temp_uri_path;
	}

	data->query = NULL;
	char *temp_query = NULL;
	if (coap_pkt->uri_query && coap_pkt->uri_query_len > 0) {
		temp_query = rt_mem_dup(coap_pkt->uri_query, coap_pkt->uri_query_len + 1);
		if (!temp_query) {
			RT_LOG_E(TAG, "temp_query alloc failed!");
			rt_data_free_item(data);
			return NULL;
		}
		temp_query[coap_pkt->uri_query_len] = '\0';
		data->query = temp_query;
	}

	return data;
}

rt_data_s *rt_receive_data_make_item(void *coap_data)
{
	rt_data_s *data = rt_receive_data_make_item_without_payload(coap_data);
	RT_VERIFY_NON_NULL_RET(data, TAG, "data", NULL);

	coap_packet_t *coap_pkt = (coap_packet_t *) coap_data;

	data->payload = NULL;
	data->payload_len = 0;
	if (coap_pkt->payload && coap_pkt->payload_len > 0) {
		data->payload_len = coap_pkt->payload_len;
		data->payload = rt_mem_dup(coap_pkt->payload, coap_pkt->payload_len);
		if (!data->payload) {
			RT_LOG_E(TAG, "data->payload alloc failed!");
			rt_data_free_item(data);
			return NULL;
		}
	}

	return data;
}

ocf_result_t rt_data_free_item(rt_data_s *data)
{
	RT_VERIFY_NON_NULL_RET(data, TAG, "data", OCF_INVALID_PARAM);

	if (data->uri_path) {
		rt_mem_free((char *)data->uri_path);
	}

	if (data->query) {
		rt_mem_free((char *)data->query);
	}

	if (data->payload) {
		rt_mem_free(data->payload);
	}

	rt_mem_free(data);
	return OCF_OK;
}
