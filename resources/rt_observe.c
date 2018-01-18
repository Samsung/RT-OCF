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
#include "rt_observe.h"
#include "rt_request_manager.h"
#include "rt_resources_manager.h"
#include "rt_resources.h"
#include "rt_data_handler.h"
#include "rt_rep.h"
#include "rt_coap.h"
#include "rt_mem.h"
#include "rt_logger.h"
#include "rt_utils.h"

#define TAG "RT_OBSERVE"

#define OBSERVE_START_SEQ_NUM 5	//TODO: number start value???

static rt_observe_s *request_observe_list = NULL;

static pthread_mutex_t request_observe_list_mutex;

ocf_result_t rt_observe_init(void)
{
	if (request_observe_list) {
		RT_LOG_D(TAG, "request_observe_list is already initialized!");
		return OCF_ALREADY_INIT;
	}

	pthread_mutex_init(&request_observe_list_mutex, NULL);

	return OCF_OK;
}

void rt_observe_terminate(void)
{
	pthread_mutex_lock(&request_observe_list_mutex);
	release_observe_list(request_observe_list);
	request_observe_list = NULL;
	pthread_mutex_unlock(&request_observe_list_mutex);

	pthread_mutex_destroy(&request_observe_list_mutex);
}

static rt_observe_s *search_registered_observe(const ocf_endpoint_s *endpoint, const char *uri_path, rt_observe_s *observe_list)
{
	rt_observe_s *cur = observe_list;
	while (cur) {
		if (rt_endpoint_is_equal(&cur->endpoint, endpoint) && strncmp(uri_path, cur->href, strlen(uri_path)) == 0) {
			RT_LOG_D(TAG, "Find registered_observe[%s]", uri_path);
			return cur;
		}
		cur = cur->next;
	}

	return NULL;
}

static rt_observe_s *rt_observe_make_new_observe_item(uint32_t seq_num, const rt_data_s *packet, const ocf_endpoint_s *endpoint)
{
	RT_VERIFY_NON_NULL_RET(packet, TAG, "packet", NULL);
	RT_VERIFY_NON_NULL_RET(endpoint, TAG, "endpoint", NULL);

	rt_observe_s *new_observe = (rt_observe_s *) rt_mem_alloc(sizeof(rt_observe_s));
	RT_VERIFY_NON_NULL_RET(new_observe, TAG, "new_observe", NULL);

	new_observe->msg_type = packet->type;
	new_observe->accept = packet->accept;
	new_observe->seq_num = seq_num;
	int uri_len = strlen(packet->uri_path);
	new_observe->href = rt_mem_alloc(sizeof(uri_len + 1));
	if (!(new_observe->href)) {
		RT_LOG_E(TAG, "new_observe->href memory alloc failed!");
		rt_mem_free(new_observe);
		return NULL;
	}
	rt_strncpy(new_observe->href, packet->uri_path, uri_len);
	rt_coap_copy_token(&new_observe->token, &packet->token);
	rt_mem_cpy(&new_observe->endpoint, endpoint, sizeof(ocf_endpoint_s));

	return new_observe;
}

static ocf_result_t rt_observe_insert_observe_item_to_list(rt_observe_s *new_observe, rt_observe_s **observe_list)
{
	RT_VERIFY_NON_NULL(new_observe, TAG, "new_observe is null");

	new_observe->next = *observe_list;
	RT_LOG_D(TAG, "\tnew_observe->next_ptr: 0x%x", new_observe->next);
	*observe_list = new_observe;

	return OCF_OK;
}

static void release_observe_item(rt_observe_s *observe_item)
{
	RT_VERIFY_NON_NULL_VOID(observe_item, TAG, "observe_item");

	rt_mem_free(observe_item->href);
	rt_mem_free(observe_item);
}

void release_observe_list(rt_observe_s *observe_list)
{
	while (observe_list) {
		rt_observe_s *item = observe_list;
		observe_list = observe_list->next;
		release_observe_item(item);
	}
}

ocf_result_t rt_observe_register(const ocf_endpoint_s *endpoint, const char *uri_path, observe_callback callback)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	RT_VERIFY_NON_NULL(endpoint, TAG, "endpoint is null");
	RT_VERIFY_NON_NULL(uri_path, TAG, "uri_path is null");
	RT_VERIFY_NON_NULL(callback, TAG, "callback");

	//TODO : observe use remote_resource not endpoint & uri_path. And version will contain in remote_resource.
	rt_token_s token;
	ocf_result_t ret = rt_request_make_request_callback_item(OBSERVE, OCF_1_0_0, callback, &token);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_request_make_request_callback_item Failed!");
		return ret;
	}

	pthread_mutex_lock(&request_observe_list_mutex);
	rt_observe_s *registered_observe = search_registered_observe(endpoint, uri_path, request_observe_list);
	pthread_mutex_unlock(&request_observe_list_mutex);
	if (registered_observe) {	//TODO : Right logic??
		rt_coap_copy_token(&registered_observe->token, &token);
		return OCF_OK;
	}

	rt_data_s register_observe_data = {
		.flags = RT_OPTION_TRANSACTION_REQUEST | RT_OPTION_OBSERVE,
		.type = COAP_TYPE_NON,	//TODO
		.code = COAP_GET,
		.observe_num = OBSERVE_REGISTER,
		.accept = OCF_1_0_0,	//TODO : same as upper comment
		.content_format = 0,
		.mid = rt_coap_get_mid(),
		.token = token,
		.uri_path = uri_path,
		.query = NULL,
		.payload = NULL,
		.payload_len = 0,
	};

	ret = rt_send_coap_payload(&register_observe_data, endpoint);
	if (ret != OCF_OK) {
		RT_LOG_E(TAG, "rt_observe failed[%d]", ret);
		return ret;
	}

	rt_observe_s *new_observe = rt_observe_make_new_observe_item(OBSERVE_REGISTER, &register_observe_data, endpoint);
	if (!new_observe) {
		RT_LOG_E(TAG, "rt_observe_make_new_observe_item failed");
		return OCF_MEM_FULL;
	}

	pthread_mutex_lock(&request_observe_list_mutex);
	ret = rt_observe_insert_observe_item_to_list(new_observe, &request_observe_list);
	pthread_mutex_unlock(&request_observe_list_mutex);
	if (ret != OCF_OK) {
		RT_LOG_E(TAG, "rt_observe_inserte_observe_item_to_list failed[%d]", ret);
		return ret;
	}

	RT_LOG_D(TAG, "OUT : %s", __func__);

	return OCF_OK;
}

static ocf_result_t rt_observe_delete_node(const rt_token_s token, const ocf_endpoint_s *endpoint, const char *uri_path, rt_observe_s **observe_list)
{
	RT_VERIFY_NON_NULL(endpoint, TAG, "endpoint");
	RT_VERIFY_NON_NULL(uri_path, TAG, "uri_path");

	rt_observe_s *cur = *observe_list;
	rt_observe_s *prev = NULL;
	rt_observe_s *target_observe = NULL;
	while (cur) {
		if (rt_endpoint_is_equal(endpoint, &cur->endpoint) && rt_coap_compare_token(&token, &cur->token) && strncmp(uri_path, cur->href, strlen(cur->href)) == 0) {
			RT_LOG_D(TAG, "Delete observe token[0x%x]", token.token[0]);
			if (prev == NULL) {
				*observe_list = cur->next;
			} else {
				prev->next = cur->next;
			}
			target_observe = cur;
			break;
		}
		prev = cur;
		cur = cur->next;
	}

	if (!target_observe) {
		RT_LOG_D(TAG, "Can't find resource[%s] with token[0x%x] observe!", uri_path, token.token[0]);
		return OCF_ERROR;
	}

	release_observe_item(target_observe);
	return OCF_OK;
}

ocf_result_t rt_observe_deregister(const ocf_endpoint_s *endpoint, const char *uri_path)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	RT_VERIFY_NON_NULL_RET(endpoint, TAG, "endpoint is null", OCF_COMM_ERROR);
	RT_VERIFY_NON_NULL_RET(uri_path, TAG, "uri_path is null", OCF_COMM_ERROR);

	pthread_mutex_lock(&request_observe_list_mutex);
	rt_observe_s *target_observe = search_registered_observe(endpoint, uri_path, request_observe_list);
	pthread_mutex_unlock(&request_observe_list_mutex);

	if (!target_observe) {
		RT_LOG_E(TAG, "Target observe[%s] not found!", uri_path);
		return OCF_ERROR;
	}
	//TODO : CON observe will receive ack from server and then remove callback item.
	ocf_result_t ret = rt_request_callback_item_release_with_token(target_observe->token);
	if (ret != OCF_OK) {
		RT_LOG_E(TAG, "rt_request_callback_item_release_with_token failed[%d]", ret);
		return ret;
	}

	rt_data_s deregister_observe_data = {
		.flags = RT_OPTION_TRANSACTION_REQUEST | RT_OPTION_OBSERVE,
		.type = target_observe->msg_type,
		.code = COAP_GET,
		.observe_num = OBSERVE_DEREGISTER,
		.accept = target_observe->accept,
		.content_format = 0,
		.mid = rt_coap_get_mid(),
		.token = target_observe->token,
		.uri_path = uri_path,
		.query = NULL,
		.payload = NULL,
		.payload_len = 0
	};

	ret = rt_send_coap_payload(&deregister_observe_data, endpoint);
	if (ret != OCF_OK) {
		RT_LOG_E(TAG, "rt_observe_deregister failed[%d]", ret);
		return ret;
	}

	pthread_mutex_lock(&request_observe_list_mutex);
	ret = rt_observe_delete_node(target_observe->token, endpoint, uri_path, &request_observe_list);
	pthread_mutex_unlock(&request_observe_list_mutex);
	if (ret != OCF_OK) {
		RT_LOG_E(TAG, "rt_observe_delete_node failed[%d]", ret);
		return ret;
	}

	RT_LOG_D(TAG, "OUT : %s", __func__);

	return OCF_OK;
}

ocf_result_t rt_observe_notify(const char *href, rt_rep_encoder_s *rep)
{
	RT_VERIFY_NON_NULL_RET(href, TAG, "href is null", OCF_INVALID_PARAM);
	RT_VERIFY_NON_NULL_RET(rep, TAG, "rep is null", OCF_INVALID_PARAM);

	RT_LOG_D(TAG, "%s IN", __func__);

	rt_resource_s *resource = rt_res_get_resource_by_href(href);
	RT_VERIFY_NON_NULL_RET(resource, TAG, "\tresource is null", OCF_INVALID_PARAM);

	rt_observe_s *cur = resource->observe_list;
	while (cur) {
		rt_data_s notify_data = {
			.flags = RT_OPTION_TRANSACTION_RESPONSE | RT_OPTION_OBSERVE,
			.type = cur->msg_type,
			.code = CONTENT_2_05,	//TODO
			.observe_num = cur->seq_num++,
			.accept = 0,
			.content_format = rep ? cur->accept : 0,
			.mid = rt_coap_get_mid(),
			.token = cur->token,
			.uri_path = cur->href,
			.query = NULL,
			.payload = rep ? rep->payload : NULL,
			.payload_len = rep ? rep->payload_size : 0
		};

		rt_endpoint_log(OCF_LOG_DEBUG, TAG, &cur->endpoint);
		RT_LOG_D(TAG, "MID : %d, token : %2X, seq_num : %d, uri : %s", notify_data.mid, notify_data.token.token[0], notify_data.observe_num, notify_data.uri_path);

		ocf_result_t ret = rt_send_coap_payload(&notify_data, &cur->endpoint);
		if (ret != OCF_OK) {
			RT_LOG_E(TAG, "ocf_res_notify failed[%d]", ret);
			return ret;
		}

		cur = cur->next;
	}

	RT_LOG_D(TAG, "%s OUT", __func__);

	return OCF_OK;
}

ocf_result_t rt_observe_handle_observe_request(rt_resource_s *resource, const rt_data_s *packet, const ocf_endpoint_s *endpoint)
{
	if (packet->observe_num == OBSERVE_REGISTER) {
		RT_LOG_D(TAG, "\tRegister observe");
		if (!rt_res_is_observable(resource)) {
			RT_LOG_D(TAG, "This resource is not observable");
			return OCF_INVALID_REQUEST_HANDLE;
		}

		rt_observe_s *registered_observe = search_registered_observe(endpoint, packet->uri_path, resource->observe_list);
		if (registered_observe) {
			rt_coap_copy_token(&registered_observe->token, &packet->token);
			return OCF_OK;
		}

		rt_observe_s *new_observe = rt_observe_make_new_observe_item(OBSERVE_START_SEQ_NUM, packet, endpoint);
		if (!new_observe) {
			RT_LOG_E(TAG, "rt_observe_make_new_observe_item failed");
			return OCF_MEM_FULL;
		}

		ocf_result_t ret = rt_observe_insert_observe_item_to_list(new_observe, &resource->observe_list);
		if (ret != OCF_OK) {
			RT_LOG_E(TAG, "rt_observe_inserte_observe_item_to_list failed[%d]", ret);
			return ret;
		}
	} else if (packet->observe_num == OBSERVE_DEREGISTER) {
		RT_LOG_D(TAG, "\tDeregister observe");
		ocf_result_t ret = rt_observe_delete_node(packet->token, endpoint, packet->uri_path, &resource->observe_list);
		if (ret != OCF_OK) {
			RT_LOG_E(TAG, "rt_observe_delete_node failed[%d]", ret);
			return ret;
		}
	}

	return OCF_OK;
}
