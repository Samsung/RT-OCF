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

#include "rt_request.h"
#include "rt_request_manager.h"
#include "rt_data_handler.h"
#include "rt_rep.h"
#include "rt_coap.h"
#include "rt_utils.h"
#include "rt_logger.h"
#include "rt_timer.h"
#include "rt_string.h"
#include "rt_mem.h"

#define TAG "RT_REQ"

static ocf_result_t rt_discovery_with_accept_version(discovery_callback callback, const char *query, ocf_version_t version)
{
	RT_VERIFY_NON_NULL_RET(callback, TAG, "callback", OCF_INVALID_PARAM);

	rt_token_s token;
	ocf_result_t ret = rt_request_make_request_callback_item(DISCOVERY, version, callback, &token);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_request_make_request_callback_item Failed!");
		return ret;
	}

	rt_data_s request_data = {
		.flags = RT_OPTION_TRANSACTION_REQUEST,
		.type = COAP_TYPE_NON,
		.code = COAP_GET,
		.observe_num = 0,
		.accept = version,
		.content_format = 0,
		.mid = rt_coap_get_mid(),
		.token = token,
		.uri_path = CORE_RES,
		.query = query,
		.payload = NULL,
		.payload_len = 0
	};

	ret = rt_send_coap_payload(&request_data, NULL);
	if (ret != OCF_OK) {
		RT_LOG_E(TAG, "rt_discovery_with_accept_version failed[%d]", ret);
		return ret;
	}
	return OCF_OK;
}

ocf_result_t rt_discovery(discovery_callback callback, const char *query)
{
	return rt_discovery_with_accept_version(callback, query, OCF_1_0_0);
}

static ocf_result_t rt_request_send(coap_method_t method, ocf_endpoint_s *endpoint, const char *uri_path, const char *query, rt_rep_encoder_s *rep, bool receive_ack, request_callback callback)
{
	RT_VERIFY_NON_NULL_RET(uri_path, TAG, "uri_path is null", OCF_COMM_ERROR);
	RT_VERIFY_NON_NULL(callback, TAG, "callback");

	//TODO : request send use remote_resource not endpoint & uri_path. And version will contain in remote_resource.
	rt_token_s token;
	ocf_result_t ret = rt_request_make_request_callback_item(REQUEST, OCF_1_0_0, callback, &token);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_request_make_request_callback_item Failed!");
		return ret;
	}

	coap_message_type_t type = receive_ack ? COAP_TYPE_CON : COAP_TYPE_NON;

	rt_data_s request_data = {
		.flags = RT_OPTION_TRANSACTION_REQUEST,
		.type = type,
		.code = method,
		.observe_num = 0,
		.accept = OCF_1_0_0,	//TODO : same as upper comment
		.content_format = rep ? OCF_1_0_0 : 0,	//TODO : same as upper comment
		.mid = rt_coap_get_mid(),
		.token = token,
		.uri_path = uri_path,
		.query = query,
		.payload = rep ? rep->payload : NULL,
		.payload_len = rep ? rep->payload_size : 0
	};

	ret = rt_send_coap_payload(&request_data, endpoint);
	if (ret != OCF_OK) {
		RT_LOG_E(TAG, "rt_request_send failed[%d]", ret);
		return ret;
	}
	return OCF_OK;
}

ocf_result_t rt_request_get_send(ocf_endpoint_s *endpoint, const char *uri_path, const char *query, bool receive_ack, request_callback callback)
{
	return rt_request_send(COAP_GET, endpoint, uri_path, query, NULL, receive_ack, callback);
}

ocf_result_t rt_request_put_send(ocf_endpoint_s *endpoint, const char *uri_path, const char *query, rt_rep_encoder_s *rep, bool receive_ack, request_callback callback)
{
	return rt_request_send(COAP_PUT, endpoint, uri_path, query, rep, receive_ack, callback);
}

ocf_result_t rt_request_post_send(ocf_endpoint_s *endpoint, const char *uri_path, const char *query, rt_rep_encoder_s *rep, bool receive_ack, request_callback callback)
{
	return rt_request_send(COAP_POST, endpoint, uri_path, query, rep, receive_ack, callback);
}

ocf_result_t rt_request_delete_send(ocf_endpoint_s *endpoint, const char *uri_path, const char *query, rt_rep_encoder_s *rep, bool receive_ack, request_callback callback)
{
	return rt_request_send(COAP_DELETE, endpoint, uri_path, query, rep, receive_ack, callback);
}

ocf_result_t rt_separate_accept(const rt_request_s *req, rt_request_s *separate_store)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	RT_VERIFY_NON_NULL(req, TAG, "req");
	if (separate_store) {
		RT_LOG_E(TAG, "separate_store should be null.");
		return OCF_INVALID_PARAM;
	}

	if (OCF_CONFIRMABLE_MSG == req->msg_type) {
		rt_coap_send_emtpy_message(req->data->mid, req->endpoint);
	}

	separate_store = (rt_request_s *) rt_mem_dup(req, sizeof(rt_request_s));
	RT_VERIFY_NON_NULL(separate_store, TAG, "separate_store");
	separate_store->endpoint = (ocf_endpoint_s *) rt_mem_dup(req->endpoint, sizeof(ocf_endpoint_s));
	if (!separate_store->endpoint) {
		RT_LOG_E(TAG, "separate_store->endpoint is null.");
		rt_mem_free(separate_store);
		return OCF_INVALID_PARAM;
	}

	rt_data_s *data = (rt_data_s *) rt_mem_alloc(sizeof(rt_data_s));
	ocf_result_t ret = rt_data_clone(data, req->data);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_data_clone is failed.");
		rt_mem_free((ocf_endpoint_s *)separate_store->endpoint);
		rt_mem_free(separate_store);
		return ret;
	}
	separate_store->data = data;

	RT_LOG_D(TAG, "OUT : %s", __func__);
	return OCF_OK;
}

ocf_result_t rt_separate_resume(rt_request_s *separate_store, rt_rep_encoder_s *rep, ocf_response_result_t response_result)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	RT_VERIFY_NON_NULL(separate_store, TAG, "separate_store");

	ocf_result_t ret = rt_response_send(separate_store, rep, response_result);
	rt_data_free_item((rt_data_s *)separate_store->data);
	rt_mem_free((ocf_endpoint_s *)separate_store->endpoint);
	rt_mem_free(separate_store);

	RT_LOG_D(TAG, "OUT : %s", __func__);
	return ret;
}

static coap_status_t ocf_response_to_coap_status(ocf_response_result_t response_result)
{
	coap_status_t ret;

	if (OCF_RESPONSE_RESOURCE_CREATED <= response_result && response_result <= OCF_RESPONSE_PROXY_NOT_SUPPORTED) {
		ret = (response_result / 100) * 32;
		ret += (response_result % 100);
		RT_LOG_D(TAG, "coap_status_t =%d", ret);
		return ret;
	}
	// TODO:: OCF_RESPONSE_SEPARATE/OCF_RESPONSE_OK/OCF_RESPONSE_SEPARATE should be applied correctly
	switch (response_result) {
	case OCF_RESPONSE_OK:
		ret = NO_ERROR;
		break;
	case OCF_RESPONSE_ERROR:
		ret = SERVICE_UNAVAILABLE_5_03;
		break;
	case OCF_RESPONSE_SEPARATE:
		ret = NO_ERROR;
		break;
	default:
		ret = SERVICE_UNAVAILABLE_5_03;
		break;

	}
	RT_LOG_D(TAG, "coap_status_t =%d", ret);
	return ret;
}

ocf_result_t rt_response_send(const rt_request_s *req, rt_rep_encoder_s *rep, ocf_response_result_t response_result)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	RT_VERIFY_NON_NULL_RET(req, TAG, "req is null", OCF_ERROR);

	coap_message_type_t coap_message_type = ((coap_message_type_t) req->msg_type == COAP_TYPE_CON) ? COAP_TYPE_ACK : COAP_TYPE_NON;

	rt_data_s response_data = {
		.flags = req->data->flags | RT_OPTION_TRANSACTION_RESPONSE,
		.type = coap_message_type,
		.code = ocf_response_to_coap_status(response_result),
		.observe_num = req->data->observe_num,
		.accept = 0,
		.content_format = rep ? req->data->accept : 0,
		.mid = req->data->mid,
		.token = req->data->token,
		.uri_path = req->data->uri_path,
		.query = NULL,
		.payload = rep ? rep->payload : NULL,
		.payload_len = rep ? rep->payload_size : 0
	};

	ocf_result_t ret = rt_send_coap_payload(&response_data, req->endpoint);
	if (ret != OCF_OK) {
		RT_LOG_E(TAG, "rt_response_send failed[%d]", ret);
		return ret;
	}

	RT_LOG_D(TAG, "OUT : %s", __func__);
	return ret;
}
