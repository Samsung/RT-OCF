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
#include "rt_resources_manager.h"
#include "rt_request.h"
#include "rt_core.h"
#include "rt_rep.h"
#include "rt_data_handler.h"
#include "rt_mem.h"
#include "rt_utils.h"
#include "rt_list.h"
#include "rt_string.h"

#define TAG "RT_RESOURCE_MANAGER"

static rt_list_s registered_res_list;
static void rt_received_packet_callback(rt_data_s *packet, const ocf_endpoint_s *endpoint);

ocf_result_t rt_resource_manager_init(const char *manufacturer_name, const char *data_model_ver)
{
	rt_list_init(&registered_res_list, sizeof(rt_resource_s), RT_MEMBER_OFFSET(rt_resource_s, node));
	rt_receive_queue_set_request_callback(rt_received_packet_callback);
	ocf_result_t ret = rt_core_res_init(manufacturer_name, data_model_ver);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_core_res_init failed!");
		rt_resource_manager_terminate();
		return ret;
	}

	return OCF_OK;
}

ocf_result_t rt_resource_manager_terminate(void)
{
	rt_core_res_terminate();

	rt_list_terminate(&registered_res_list, (rt_list_release_item_cb) rt_res_delete_resource_components);

	return OCF_OK;
}

rt_resource_s *rt_res_get_resource_by_href(const char *href)
{
	rt_node_s *itr = registered_res_list.head;
	int len = strlen(href);

	RT_VERIFY_NON_ZERO_RET(len, TAG, "len of href is zero", NULL);

	while (itr) {
		rt_resource_s *resource = (rt_resource_s *) rt_list_get_item(&registered_res_list, itr);
		RT_VERIFY_NON_NULL_RET(resource, TAG, "getting item from list is NULL", NULL);
		if (!strncmp(href, resource->href, len)) {
			return resource;
		}
		itr = itr->next;
	}

	return NULL;
}

ocf_result_t rt_res_register_resource(rt_resource_s *resource)
{
	RT_VERIFY_NON_NULL_RET(resource, TAG, "resource is NULL ", OCF_RESOURCE_ERROR);

	if (rt_res_get_resource_by_href(resource->href)) {
		return OCF_RESOURCE_ERROR;
	}

	rt_list_insert(&registered_res_list, &(resource->node));
	return OCF_OK;
}

ocf_result_t rt_res_deregister_resource(rt_resource_s *resource)
{
	RT_VERIFY_NON_NULL_RET(resource, TAG, "resource is NULL ", OCF_RESOURCE_ERROR);

	if (!rt_list_search(&registered_res_list, RT_MEMBER_OFFSET(rt_resource_s, href), RT_MEMBER_SIZE(rt_resource_s, href), resource->href)) {
		RT_LOG_W(TAG, "%s resource is not a registered resource.");
		return OCF_OK;
	}

	rt_list_delete_by_node(&registered_res_list, &(resource->node));

	return OCF_OK;
}

const rt_list_s *rt_res_get_registered_list(void)
{
	return &registered_res_list;
}

static void rt_received_packet_callback(rt_data_s *packet, const ocf_endpoint_s *endpoint)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	rt_request_s request = { 0, };

	request.data = packet;
	request.msg_type = (ocf_message_type_t) packet->type;

	if (packet->query) {
		size_t query_len = strlen(packet->query);
		if (query_len > 0) {
			int i;
			rt_parse_query(&request.queries.query_list, (char *)request.data->query, query_len);

			if (request.queries.query_list.query_num > 0) {
				for (i = 0; i < request.queries.query_list.query_num; i++) {
					if (strncmp(OIC_RT_NAME, request.queries.query_list.query[i].name, sizeof(OIC_RT_NAME)) == 0) {
						request.queries.rt_query = request.queries.query_list.query[i].value;
					} else if (strncmp(OIC_IF_NAME, request.queries.query_list.query[i].name, sizeof(OIC_IF_NAME)) == 0) {
						request.queries.if_query = request.queries.query_list.query[i].value;
					}
				}
			}
			RT_LOG_D(TAG, "rt query : %s", request.queries.rt_query);
			RT_LOG_D(TAG, "if query: %s", request.queries.if_query);
			for (i = 0; i < request.queries.query_list.query_num; i++) {
				RT_LOG_D(TAG, "[QUERY] %s : %s", request.queries.query_list.query[i].name, request.queries.query_list.query[i].value);
			}
		}
	}

	request.endpoint = endpoint;

	if (false == rt_sec_pe_check_permission(&request, packet->code)) {
		RT_LOG_E(TAG, "Access Denied!!");
		rt_response_send((rt_request_s *)&request, NULL, OCF_RESPONSE_UNAUTHORIZED_REQ);
		goto exit;
	}

	if (0 == strncmp(request.data->uri_path, CORE_RES, strlen(CORE_RES))) {
		if (request.queries.if_query == NULL || (strncmp(request.queries.if_query, OIC_IF_BASELINE_VALUE, strlen(OIC_IF_BASELINE_VALUE)) == 0) || (strncmp(request.queries.if_query, OIC_IF_LL_VALUE, strlen(OIC_IF_LL_VALUE)) == 0)) {
			rt_core_res_discovery_handler(&request);
		} else {
			rt_response_send(&request, NULL, OCF_RESPONSE_BAD_REQ);
		}

	} else {
		rt_resource_s *res = rt_res_get_resource_by_href(request.data->uri_path);

		if (NULL == res) {
			rt_response_send(&request, NULL, OCF_RESPONSE_RESOURCE_NOT_FOUND);
			goto exit;
		}

		if (request.queries.if_query && (OCF_ERROR == rt_res_is_interface_supported(res, rt_res_get_interface_enum_value(request.queries.if_query)))) {
			RT_LOG_E(TAG, "Invalid if query received![%s]", request.queries.if_query);
			rt_response_send(&request, NULL, OCF_RESPONSE_BAD_REQ);
			goto exit;
		}

		rt_rep_decoder_s *rep = NULL;
		if (packet->payload && packet->payload > 0) {
			rep = rt_rep_decoder_init(packet->payload, packet->payload_len);
			if (rep == NULL) {
				goto exit;
			}
		}

		switch (packet->code) {
		case COAP_GET:

			// oic.if.ll
			// TODO
			if (rt_res_get_interface_enum_value(request.queries.if_query) & OIC_IF_LL) {
				// TODO  ,rep must be filled
				rt_response_send(&request, NULL, OCF_RESPONSE_OK);
			} else if (res->get_handler) {
				if (RT_OPTION_OBSERVE & packet->flags) {
					ocf_result_t ret = rt_observe_handle_observe_request(res, packet, endpoint);
					if (OCF_OK == ret) {
						if (packet->observe_num == OBSERVE_DEREGISTER) {
							packet->flags &= ~RT_OPTION_OBSERVE;
						}
					} else {
						packet->flags &= ~RT_OPTION_OBSERVE;
					}
				}
				res->get_handler((ocf_request_s) & request, NULL);
			} else {
				rt_response_send(&request, NULL, OCF_RESPONSE_NOT_IMPLEMENTED);
			}
			break;
		case COAP_POST:
			if (res->post_handler) {
				res->post_handler((ocf_request_s) & request, (ocf_rep_decoder_s) rep);
			} else {
				rt_response_send(&request, NULL, OCF_RESPONSE_NOT_IMPLEMENTED);
			}
			break;
		case COAP_PUT:
			if (res->put_handler) {
				res->put_handler((ocf_request_s) & request, (ocf_rep_decoder_s) rep);
			} else {
				rt_response_send(&request, NULL, OCF_RESPONSE_NOT_IMPLEMENTED);
			}
			break;
		case COAP_DELETE:
			if (res->delete_handler) {
				res->delete_handler((ocf_request_s) & request, (ocf_rep_decoder_s) rep);
			} else {
				rt_response_send(&request, NULL, OCF_RESPONSE_NOT_IMPLEMENTED);
			}
			break;
		}
		if (rep) {
			rt_rep_decoder_release(rep);
		}
	}

exit:
	rt_query_free(&request.queries.query_list);

	RT_LOG_D(TAG, "%s OUT", __func__);
}

bool rt_res_is_discoverable(rt_resource_s *resource)
{
	RT_VERIFY_NON_NULL_RET(resource, TAG, "resource is NULL", false);
	return (resource->p) & RT_DISCOVERABLE ? true : false;
}

bool rt_res_is_observable(rt_resource_s *resource)
{
	RT_VERIFY_NON_NULL_RET(resource, TAG, "resource is NULL", false);
	return (resource->p) & RT_OBSERVABLE ? true : false;
}

bool rt_res_is_secure(rt_resource_s *resource)
{
	RT_VERIFY_NON_NULL_RET(resource, TAG, "resource is NULL", false);
	return resource->is_secure;
}

bool rt_res_is_discoverable_by_href(const char *request_href)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	rt_resource_s *resource = rt_res_get_resource_by_href(request_href);

	RT_LOG_D(TAG, "%s OUT", __func__);
	return rt_res_is_discoverable(resource);
}
