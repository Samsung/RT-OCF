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

#include "rt_request_manager.h"
#include "rt_remote_resource.h"
#include "rt_request.h"
#include "rt_observe.h"
#include "rt_receive_queue.h"
#include "rt_coap.h"
#include "rt_coap_transactions.h"
#include "rt_coap_block.h"
#include "rt_data_handler.h"
#include "rt_mem.h"
#include "rt_utils.h"
#include "rt_logger.h"
#include "rt_timer.h"
#include "rt_rep.h"
#include "rt_string.h"

#define TAG "RT_REQ_MGR"

typedef struct {
	rt_token_s token;
	rt_timer_s ttl;
	request_type_t type;
	ocf_version_t accept;
	ocf_version_t content_format;
	union {
		discovery_callback discovery_cb;
		request_callback request_cb;
		observe_callback observe_cb;
	};
	rt_node_s node;
} request_callback_item_s;

static rt_list_s request_callback_list;

static void response_handler(const rt_data_s *packet, const ocf_endpoint_s *endpoint);
void rt_remote_resource_release_all_item(ocf_remote_resource_s *remote_resource);

ocf_result_t rt_request_manager_init(void)
{
	if (request_callback_list.count != 0) {
		return OCF_ALREADY_INIT;
	}
	rt_list_init(&request_callback_list, sizeof(request_callback_item_s), RT_MEMBER_OFFSET(request_callback_item_s, node));
	rt_receive_queue_set_response_callback(response_handler);
	ocf_result_t ret = rt_observe_init();
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_observe_init failed!");
		return ret;
	}

	return OCF_OK;
}

ocf_result_t rt_request_manager_terminate(void)
{
	rt_observe_terminate();
	rt_list_terminate(&request_callback_list, NULL);
	return OCF_OK;
}

static ocf_result_t make_coap_payload(rt_data_s *data, const ocf_endpoint_s *endpoint)
{
	coap_packet_t msg[1];

	rt_coap_init_message(msg, data->type, data->code, data->mid);
	rt_coap_set_header_uri_path(msg, data->uri_path);
	rt_coap_set_token(msg, data->token.token, data->token.len);

	if (RT_OPTION_OBSERVE & data->flags) {
		rt_coap_set_header_observe(msg, data->observe_num);
	}

	coap_transaction_type_t trans_type = data->flags & RT_OPTION_TRANSACTION_REQUEST ? COAP_TRANSACTION_REQUEST : COAP_TRANSACTION_RESPONSE;
	if (COAP_TRANSACTION_REQUEST == trans_type) {
		coap_content_format_t accept = 0;
		if (data->accept == OCF_1_0_0) {
			accept = APPLICATION_VND_OCF_CBOR;
			rt_coap_set_header_accept(msg, accept);
			rt_coap_set_header_ocf_accept(msg, data->accept);
		} else if (data->accept == OIC_1_1_0) {
			accept = APPLICATION_CBOR;
			rt_coap_set_header_accept(msg, accept);
			rt_coap_set_header_ocf_accept(msg, data->accept);
		}
	}

	if (RT_OPTION_BLOCK & data->flags) {
		if (OCF_OK != rt_coap_set_block_response_info(msg, data, endpoint)) {
			RT_LOG_E(TAG, "rt_coap_set_block_response_info failed!");
			return OCF_ERROR;
		}
	}

	if (data->query) {
		rt_coap_set_header_uri_query(msg, data->query);
	}

	if (data->payload && data->payload_len > 0) {
		coap_content_format_t content_format = 0;
		if (data->content_format == OCF_1_0_0) {
			content_format = APPLICATION_VND_OCF_CBOR;
		} else if (data->content_format == OIC_1_1_0) {
			content_format = APPLICATION_CBOR;
		} else {
			RT_LOG_E(TAG, "Unsupported version!");
			return OCF_ERROR;
		}
		rt_coap_set_header_content_format(msg, content_format);
		rt_coap_set_header_ocf_content_format(msg, data->content_format);
		rt_coap_set_payload(msg, data->payload, data->payload_len);
	}

	RT_LOG_D(TAG, "mid : %d", data->mid);
	RT_LOG_D(TAG, "uri_path : %s", data->uri_path);
	RT_LOG_D(TAG, "token : 0x%x", data->token.token[0]);

	coap_transaction_t *t = rt_coap_new_transaction(trans_type, data->mid, endpoint);
	RT_VERIFY_NON_NULL_RET(t, TAG, "transaction is null", OCF_MEM_FULL);

	ocf_result_t ret = rt_coap_serialize_message_n_set_signal(msg, t);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_coap_serialize_message_n_set_signal failed!");
		return ret;
	}

	return OCF_OK;
}

ocf_result_t rt_send_coap_payload(rt_data_s *send_data, const ocf_endpoint_s *endpoint)
{
	RT_VERIFY_NON_NULL_RET(send_data, TAG, "send_data", OCF_INVALID_PARAM);
	ocf_result_t ret = OCF_ERROR;
	if (rt_coap_block_is_block_need(send_data, endpoint)) {
		ret = rt_coap_new_block_transaction(send_data, endpoint);
	} else {
		ret = make_coap_payload(send_data, endpoint);
	}
	return ret;
}

ocf_result_t rt_request_make_request_callback_item(request_type_t type, ocf_version_t version, void *callback, rt_token_s *token)
{
	RT_VERIFY_NON_NULL_RET(callback, TAG, "callback", OCF_INVALID_PARAM);

	request_callback_item_s *item = (request_callback_item_s *) rt_mem_alloc(sizeof(request_callback_item_s));
	RT_VERIFY_NON_NULL_RET(item, TAG, "item alloc failed", OCF_MEM_FULL);

	item->type = type;
	if (DISCOVERY == type) {
		item->discovery_cb = callback;
	} else if (REQUEST == type) {
		item->request_cb = callback;
	} else if (OBSERVE == type) {
		item->observe_cb = callback;
	} else {
		RT_LOG_E(TAG, "Invalid request type!");
		rt_mem_free(item);
		item = NULL;
		return OCF_INVALID_PARAM;
	}
	item->accept = version;

	if (OBSERVE != type) {
		rt_timer_set(&item->ttl, TTL_INTERVAL * RT_CLOCK_SECOND);
	}
	item->token.len = TOKEN_LEN;
	rt_random_rand_to_buffer(item->token.token, item->token.len);	
	rt_coap_copy_token(token, &item->token);	
	rt_list_insert(&request_callback_list, &(item->node));

	return OCF_OK;
}

static request_callback_item_s *get_callback_item_by_token(const rt_token_s token)
{
	rt_node_s *itr = request_callback_list.head;
	while (itr) {
		request_callback_item_s *item = (request_callback_item_s *) rt_list_get_item(&request_callback_list, itr);
		RT_VERIFY_NON_NULL_RET(item, TAG, "getting item from list is NULL", NULL);
		if (rt_coap_compare_token(&item->token, &token)) {
			return item;
		} else if (item->ttl.interval != 0 && rt_timer_expired(&item->ttl)) {
			RT_LOG_D(TAG, "Request callback item[0x%x] ttl is expired!", item->token.token[0]);
			request_callback_item_s *info = (request_callback_item_s *) rt_list_delete_by_node(&request_callback_list, &item->node);
			if (info) {
				rt_mem_free(info);
				info = NULL;
			}
		}
		itr = itr->next;
	}
	return NULL;
}

static void rt_request_callback_item_release(request_callback_item_s *callback_item)
{
	RT_VERIFY_NON_NULL_VOID(callback_item, TAG, "callback_item");

	rt_list_delete_by_node(&request_callback_list, &(callback_item->node));
	rt_mem_free(callback_item);
}

ocf_result_t rt_request_callback_item_release_with_token(rt_token_s token)
{
	request_callback_item_s *callback_item = get_callback_item_by_token(token);
	if (!callback_item) {
		RT_LOG_E(TAG, "can't find callback_item using token[0x%x]", token.token[0]);
		return OCF_ERROR;
	}

	rt_request_callback_item_release(callback_item);
	callback_item = NULL;

	return OCF_OK;
}

static ocf_response_result_t coap_status_to_ocf_response(coap_status_t coap_result)
{
	ocf_response_result_t ret;

	if (CREATED_2_01 <= coap_result && coap_result <= PROXYING_NOT_SUPPORTED_5_05) {
		ret = (coap_result / 32) * 100;
		ret += (coap_result % 32);
		RT_LOG_D(TAG, "ocf_response_result_t =%d", ret);
		return ret;
	}
	// TODO:: OCF_RESPONSE_SEPARATE should be applied
	switch (coap_result) {
	case NO_ERROR:
		ret = OCF_RESPONSE_OK;
		break;
	default:
		ret = OCF_RESPONSE_ERROR;
		break;
	}

	RT_LOG_D(TAG, "ocf_response_result_t =%d", ret);
	return ret;
}

static void response_handler(const rt_data_s *packet, const ocf_endpoint_s *endpoint)
{
	RT_VERIFY_NON_NULL_VOID(packet, TAG, "packet");
	RT_VERIFY_NON_NULL_VOID(endpoint, TAG, "endpoint");

	RT_LOG_D(TAG, "%s IN", __func__);
	request_callback_item_s *callback_item = get_callback_item_by_token(packet->token);
	RT_VERIFY_NON_NULL_VOID(callback_item, TAG, "callback_item");

	rt_rep_decoder_s *rep = NULL;

	if (packet->payload && packet->payload_len > 0) {
		rep = rt_rep_decoder_init(packet->payload, packet->payload_len);
	}

	if (callback_item->type == DISCOVERY) {
		RT_LOG_D(TAG, "DISCOVERY response received!");
		RT_VERIFY_NON_NULL_VOID(rep, TAG, "rep of discovery response is null");
		//ToDo : Whether accept option is ocf 1.1 spec or not
		ocf_remote_resource_s *remote_resource = parse_discovery_payload_ocf_1_0(rep);
		// ocf_remote_resource_s *remote_resource = parse_discovery_payload_oic_1_1(rep);
		if (remote_resource) {
			callback_item->discovery_cb(remote_resource, coap_status_to_ocf_response(packet->code));
			rt_remote_resource_release_all_item(remote_resource);
		}
	} else if (callback_item->type == REQUEST) {
		RT_LOG_D(TAG, "REQUEST response received!");
		callback_item->request_cb((ocf_rep_decoder_s) rep, coap_status_to_ocf_response(packet->code));
		rt_request_callback_item_release(callback_item);
		callback_item = NULL;
	} else if (callback_item->type == OBSERVE) {
		RT_LOG_D(TAG, "OBSERVE response received!");
		callback_item->observe_cb((ocf_rep_decoder_s) rep, coap_status_to_ocf_response(packet->code));
	} else {
		RT_LOG_E(TAG, "Wrong callback_item type! %d", callback_item->type);
		rt_request_callback_item_release(callback_item);
		callback_item = NULL;
	}

	if (rep) {
		rt_rep_decoder_release(rep);
	}

	RT_LOG_D(TAG, "%s OUT", __func__);
}
