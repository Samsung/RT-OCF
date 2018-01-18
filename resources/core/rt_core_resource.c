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
#include "rt_core.h"
#include "rt_request.h"
#include "rt_resources_manager.h"
#include "rt_data_handler.h"
#include "rt_rep.h"
#include "rt_utils.h"
#include "rt_uuid.h"
#include "rt_mem.h"

#define TAG "RT_CORE_RES"

static rt_rep_encoder_s *rt_make_representation_for_get_links_for_oic_1_1(const char *rt_query);
static rt_rep_encoder_s *rt_create_oic_res_representation_oic_1_1(const ocf_request_query_set_s *queries);
static rt_rep_encoder_s *rt_create_oic_res_representation_ocf_1_0(const ocf_request_query_set_s *queries);

ocf_result_t rt_core_res_init(const char *manufacturer_name, const char *data_model_ver)
{
	ocf_result_t ret = OCF_OK;
	rt_resource_s *oic_p_resource = NULL;
	rt_resource_s *oic_d_resource = NULL;
	rt_resource_s *introspection_resource = NULL;

	oic_p_resource = rt_core_make_oic_p(manufacturer_name);
	if (!oic_p_resource) {
		RT_LOG_E(TAG, "Failure to make %s", CORE_P);
		goto errors;
	}
	if ((ret = rt_res_register_resource(oic_p_resource)) != OCF_OK) {
		RT_LOG_E(TAG, "Failure to register %s", CORE_P);
		goto errors;
	}

	oic_d_resource = rt_core_make_oic_d(data_model_ver);
	if (!oic_d_resource) {
		RT_LOG_E(TAG, "Failure to make %s", CORE_D);
		goto errors;
	}
	if ((ret = rt_res_register_resource(oic_d_resource)) != OCF_OK) {
		RT_LOG_E(TAG, "Failure to register %s", CORE_D);
		goto errors;
	}

	introspection_resource = rt_core_make_introspection(CORE_INTROSPECTION);
	if (!introspection_resource) {
		RT_LOG_E(TAG, "Failure to make %s", CORE_INTROSPECTION);
		goto errors;
	}
	if ((ret = rt_res_register_resource(introspection_resource)) != OCF_OK) {
		RT_LOG_E(TAG, "Failure to register %s", CORE_INTROSPECTION);
		goto errors;
	}

	return OCF_OK;

errors:
	if (oic_p_resource) {
		rt_res_deregister_resource(oic_p_resource);
		rt_res_delete_resource(oic_p_resource);
		rt_core_remove_oic_p();
	}
	if (oic_d_resource) {
		rt_res_deregister_resource(oic_d_resource);
		rt_res_delete_resource(oic_d_resource);
		rt_core_remove_oic_d();
	}
	if (introspection_resource) {
		rt_res_deregister_resource(introspection_resource);
		rt_res_delete_resource(introspection_resource);
		rt_core_remove_introspection();
	}

	return ret;
}

ocf_result_t rt_core_res_terminate(void)
{
	rt_core_remove_oic_p();
	rt_core_remove_oic_d();
	rt_core_remove_introspection();

	return OCF_OK;
}

void rt_core_res_discovery_handler(const rt_request_s *request)
{
	RT_VERIFY_NON_NULL_VOID(request, TAG, "request");
	RT_LOG_D(TAG, "IN : %s", __func__);

	rt_rep_encoder_s *rep = NULL;

	if (request->data->accept == OCF_1_0_0) {
		rep = rt_create_oic_res_representation_ocf_1_0(&request->queries);
	} else if (request->data->accept == OIC_1_1_0) {
		rep = rt_create_oic_res_representation_oic_1_1(&request->queries);
	}

	if (rep) {
		rt_response_send(request, rep, OCF_RESPONSE_CONTENT);
		rt_rep_encoder_release(rep);
	} else {
		rt_response_send(request, NULL, OCF_RESPONSE_RESOURCE_NOT_FOUND);
	}

	RT_LOG_D(TAG, "OUT : %s", __func__);
}

static rt_rep_encoder_s *rt_get_rt_representation(rt_resource_s *resource)
{
	rt_rep_encoder_s *rt_array = rt_rep_encoder_init(OCF_REP_ARRAY);
	rt_resource_type_list_s *resource_type_node = resource->resource_types;
	while (resource_type_node) {
		rt_rep_add_string_to_array(rt_array, resource_type_node->resource_type);
		resource_type_node = resource_type_node->next;
	}
	return rt_array;
}

#define EP_TO_STR_LEN 60
static char *rt_convert_ep_to_string(ocf_protocol_t scheme, const char *ip, uint16_t port)
{
	char *buf = rt_mem_alloc(EP_TO_STR_LEN);
	RT_VERIFY_NON_NULL_RET(buf, TAG, "buf", NULL);
	memset(buf, 0, EP_TO_STR_LEN);

	switch (scheme) {
	case OCF_COAP:
		snprintf(buf, EP_TO_STR_LEN, "coap://%s:%d", ip, port);
		break;
	case OCF_COAPS:
		snprintf(buf, EP_TO_STR_LEN, "coaps://%s:%d", ip, port);
		break;
	case OCF_HTTP:
		snprintf(buf, EP_TO_STR_LEN, "http://%s:%d", ip, port);
		break;
	case OCF_HTTPS:
		snprintf(buf, EP_TO_STR_LEN, "https://%s:%d", ip, port);
		break;
	case OCF_COAP_TCP:
		snprintf(buf, EP_TO_STR_LEN, "coap+tcp://%s:%d", ip, port);
		break;
	case OCF_COAPS_TCP:
		snprintf(buf, EP_TO_STR_LEN, "coaps+tcp://%s:%d", ip, port);
		break;
	default:
		break;
	}

	return buf;
}

static rt_rep_encoder_s *rt_get_eps_representation(rt_resource_s *resource)
{
	char ip[20];
	rt_rep_encoder_s *eps_array = rt_rep_encoder_init(OCF_REP_ARRAY);
	rt_transport_get_local_ipv4(ip, sizeof(ip));
	uint16_t port = 0;
	ocf_protocol_t scheme = 1;
	char *ep;

	do {
		ep = NULL;
		//GET
		if (resource->scheme & OCF_COAP & scheme) {
			rt_udp_get_normal_port_v4(&port);
			ep = rt_convert_ep_to_string(OCF_COAP, ip, port);
		} else if (resource->scheme & OCF_COAPS & scheme) {
			rt_udp_get_secure_port_v4(&port);
			ep = rt_convert_ep_to_string(OCF_COAPS, ip, port);
		} else if (resource->scheme & OCF_COAP_TCP & scheme) {
			rt_tcp_get_normal_port_v4(&port);
			ep = rt_convert_ep_to_string(OCF_COAP_TCP, ip, port);
		} else if (resource->scheme & OCF_COAPS_TCP & scheme) {
			rt_tcp_get_secure_port_v4(&port);
			ep = rt_convert_ep_to_string(OCF_COAPS_TCP, ip, port);
		}

		if (ep) {
			rt_rep_encoder_s *ep_map = rt_rep_encoder_init(OCF_REP_MAP);
			rt_rep_add_string_to_map(ep_map, "ep", ep);
			rt_rep_add_map_to_array(eps_array, ep_map);
			rt_rep_encoder_release(ep_map);
			rt_mem_free(ep);
		}

	} while ((scheme <<= 1) <= (1 << 5));

	return eps_array;
}

static rt_rep_encoder_s *rt_get_if_representation(rt_resource_s *resource)
{
	uint8_t interface = 1;
	rt_rep_encoder_s *if_array = rt_rep_encoder_init(OCF_REP_ARRAY);
	do {
		if (resource->interfaces & interface) {
			char interface_str[20];
			rt_res_get_interface_string_value(interface, interface_str);
			rt_rep_add_string_to_array(if_array, interface_str);
		}
	} while ((interface <<= 1) <= (1 << 6));

	return if_array;
}

static rt_rep_encoder_s *rt_make_res_map_for_oic_1_1(rt_resource_s *resource)
{
	rt_rep_encoder_s *sub_map;

	sub_map = rt_rep_encoder_init(OCF_REP_MAP);
	rt_rep_add_string_to_map(sub_map, "href", resource->href);

	rt_rep_encoder_s *rt_array = rt_get_rt_representation(resource);
	rt_rep_add_array_to_map(sub_map, OIC_RT_NAME, rt_array);
	rt_rep_encoder_release(rt_array);

	rt_rep_encoder_s *if_array = rt_get_if_representation(resource);
	rt_rep_add_array_to_map(sub_map, "if", if_array);
	rt_rep_encoder_release(if_array);

	rt_rep_encoder_s *policy_map = rt_rep_encoder_init(OCF_REP_MAP);
	rt_rep_add_int_to_map(policy_map, "bm", resource->p);

	if (resource->is_secure) {
		rt_rep_add_bool_to_map(policy_map, "sec", resource->is_secure);

		int udp_secure_port = 0;
		rt_udp_get_secure_port_v4(&udp_secure_port);
		rt_rep_add_int_to_map(policy_map, "port", udp_secure_port);
	}

	rt_rep_add_map_to_map(sub_map, "p", policy_map);
	rt_rep_encoder_release(policy_map);

	return sub_map;
}

static rt_rep_encoder_s *rt_make_representation_for_get_links_for_oic_1_1(const char *rt_query)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	const rt_list_s *registered_res_list = rt_res_get_registered_list();
	rt_rep_encoder_s *sub_array = rt_rep_encoder_init(OCF_REP_ARRAY);

	rt_node_s *itr = registered_res_list->head;
	while (itr) {
		rt_resource_s *resource = (rt_resource_s *) rt_list_get_item(registered_res_list, itr);
		RT_VERIFY_NON_NULL_RET(resource, TAG, "getting item from list is NULL", NULL);

		if (rt_res_is_discoverable(resource) && OCF_OK == rt_res_is_resource_type_supported(resource, rt_query)) {
			rt_rep_encoder_s *sub_map = rt_make_res_map_for_oic_1_1(resource);

			rt_rep_add_map_to_array(sub_array, sub_map);
			rt_rep_encoder_release(sub_map);
		}
		itr = itr->next;
	}
	RT_LOG_D(TAG, "OUT : %s", __func__);
	return sub_array;
}

static rt_rep_encoder_s *rt_create_oic_res_representation_oic_1_1(const ocf_request_query_set_s *queries)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	const char *rt_query = queries->rt_query;
	//root array
	rt_rep_encoder_s *oic_res_rep = rt_rep_encoder_init(OCF_REP_ARRAY);
	rt_rep_encoder_s *root_map = rt_rep_encoder_init(OCF_REP_MAP);

	char uuid_str[RT_UUID_STR_LEN];
	rt_sec_doxm_get_deviceuuid(uuid_str);
	rt_rep_add_string_to_map(root_map, "di", uuid_str);

	if ((queries->if_query != NULL) && (strncmp(queries->if_query, OIC_IF_BASELINE_VALUE, strlen(OIC_IF_BASELINE_VALUE)) == 0)) {
		rt_rep_encoder_s *array = rt_rep_encoder_init(OCF_REP_ARRAY);
		rt_rep_add_string_to_array(array, DISCOVERY_RES_TYPE_DEFAULT);
		rt_rep_add_array_to_map(root_map, "rt", array);
		rt_rep_encoder_release(array);

		array = rt_rep_encoder_init(OCF_REP_ARRAY);
		rt_rep_add_string_to_array(array, OIC_IF_BASELINE_VALUE);
		rt_rep_add_string_to_array(array, OIC_IF_LL_VALUE);

		rt_rep_add_array_to_map(root_map, "if", array);
		rt_rep_encoder_release(array);
	}

	rt_rep_encoder_s *sub_array = rt_make_representation_for_get_links_for_oic_1_1(rt_query);
	if (sub_array == NULL) {
		rt_rep_encoder_release(root_map);
		rt_rep_encoder_release(oic_res_rep);
		return NULL;
	} else if (sub_array->count == 0) {
		RT_LOG_D(TAG, "can't find %s type resources.", rt_query);
		rt_rep_encoder_release(sub_array);
		rt_rep_encoder_release(root_map);
		rt_rep_encoder_release(oic_res_rep);
		return NULL;
	}
	rt_rep_add_array_to_map(root_map, "links", sub_array);
	rt_rep_encoder_release(sub_array);

	rt_rep_add_map_to_array(oic_res_rep, root_map);
	rt_rep_encoder_release(root_map);

	RT_LOG_D(TAG, "OUT : %s", __func__);

	return oic_res_rep;
}

#define ANCHOR_STR_LEN 44
static rt_rep_encoder_s *rt_make_submap_for_ocf_1_0(rt_resource_s *resource)
{
	rt_rep_encoder_s *sub_map;

	sub_map = rt_rep_encoder_init(OCF_REP_MAP);
	rt_rep_add_string_to_map(sub_map, "href", resource->href);

	char uuid_str[RT_UUID_STR_LEN];
	char anchor_str[ANCHOR_STR_LEN];
	memset(anchor_str, 0, ANCHOR_STR_LEN);

	rt_sec_doxm_get_deviceuuid(uuid_str);
	snprintf(anchor_str, ANCHOR_STR_LEN, "ocf://%s", uuid_str);
	rt_rep_add_string_to_map(sub_map, "anchor", anchor_str);

	rt_rep_encoder_s *rt_array = rt_get_rt_representation(resource);
	rt_rep_add_array_to_map(sub_map, "rt", rt_array);
	rt_rep_encoder_release(rt_array);

	rt_rep_encoder_s *if_array = rt_get_if_representation(resource);
	rt_rep_add_array_to_map(sub_map, "if", if_array);
	rt_rep_encoder_release(if_array);

	rt_rep_encoder_s *policy_map = rt_rep_encoder_init(OCF_REP_MAP);
	rt_rep_add_int_to_map(policy_map, "bm", resource->p);

	rt_rep_add_map_to_map(sub_map, "p", policy_map);
	rt_rep_encoder_release(policy_map);

	if (resource->scheme) {
		rt_rep_encoder_s *eps_array = rt_get_eps_representation(resource);
		rt_rep_add_array_to_map(sub_map, "eps", eps_array);
		rt_rep_encoder_release(eps_array);
	}
	return sub_map;
}

static rt_rep_encoder_s *rt_create_oic_res_representation_ocf_1_0(const ocf_request_query_set_s *queries)
{
	RT_LOG_D(TAG, "IN : %s", __func__);

	rt_rep_encoder_s *oic_res_rep = rt_rep_encoder_init(OCF_REP_ARRAY);
	const rt_list_s *registered_res_list = rt_res_get_registered_list();

	rt_node_s *itr = registered_res_list->head;
	while (itr) {
		rt_resource_s *resource = (rt_resource_s *) rt_list_get_item(registered_res_list, itr);
		RT_VERIFY_NON_NULL_RET(resource, TAG, "getting item from list is NULL", NULL);

		if (rt_res_is_discoverable(resource) && OCF_OK == rt_res_is_resource_type_supported(resource, queries->rt_query)) {
			rt_rep_encoder_s *sub_map = rt_make_submap_for_ocf_1_0(resource);

			rt_rep_add_map_to_array(oic_res_rep, sub_map);
			rt_rep_encoder_release(sub_map);
		}
		itr = itr->next;
	}

	if (!oic_res_rep || oic_res_rep->count == 0) {
		RT_LOG_D(TAG, "can't find %s type resources.", queries->rt_query);
		rt_rep_encoder_release(oic_res_rep);
		return NULL;
	}

	if ((queries->if_query != NULL) && (strncmp(queries->if_query, OIC_IF_BASELINE_VALUE, strlen(OIC_IF_BASELINE_VALUE)) == 0)) {
		rt_rep_encoder_s *root_array = rt_rep_encoder_init(OCF_REP_ARRAY);
		rt_rep_encoder_s *root_map = rt_rep_encoder_init(OCF_REP_MAP);

		rt_rep_encoder_s *array = rt_rep_encoder_init(OCF_REP_ARRAY);
		rt_rep_add_string_to_array(array, DISCOVERY_RES_TYPE_DEFAULT);
		rt_rep_add_array_to_map(root_map, "rt", array);
		rt_rep_encoder_release(array);

		array = rt_rep_encoder_init(OCF_REP_ARRAY);
		rt_rep_add_string_to_array(array, OIC_IF_BASELINE_VALUE);
		rt_rep_add_string_to_array(array, OIC_IF_LL_VALUE);

		rt_rep_add_array_to_map(root_map, "if", array);
		rt_rep_encoder_release(array);

		rt_rep_add_array_to_map(root_map, "links", oic_res_rep);
		rt_rep_encoder_release(oic_res_rep);

		rt_rep_add_map_to_array(root_array, root_map);
		rt_rep_encoder_release(root_map);
		oic_res_rep = root_array;
	}

	RT_LOG_D(TAG, "OUT : %s", __func__);
	return oic_res_rep;
}
