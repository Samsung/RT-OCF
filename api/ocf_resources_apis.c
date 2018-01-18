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

#include "rt_resources.h"
#include "rt_collection.h"
#include "rt_resources_manager.h"
#include "rt_sec_persistent_storage.h"

ocf_result_t ocf_res_set_default_interface(ocf_resource_s resource, ocf_interface_mask_t interface)
{
	return rt_res_set_default_interface((rt_resource_s *) resource, interface);
}

ocf_result_t ocf_res_get_default_interface(ocf_resource_s resource, uint8_t *interface)
{
	return rt_res_get_default_interface((rt_resource_s *) resource, interface);
}

ocf_result_t ocf_res_is_interface_supported(ocf_resource_s resource, ocf_interface_mask_t interface)
{
	return rt_res_is_interface_supported((rt_resource_s *) resource, interface);
}

ocf_result_t ocf_res_set_interface(ocf_resource_s resource, ocf_interface_mask_t interface)
{
	return rt_res_set_interface((rt_resource_s *) resource, interface);
}

ocf_result_t ocf_res_get_interface_string_value(uint8_t interfaces, char *interface_str)
{
	return rt_res_get_interface_string_value(interfaces, interface_str);
}

ocf_interface_mask_t ocf_res_get_interface_enum_value(char *interface_str)
{
	return rt_res_get_interface_enum_value(interface_str);
}

ocf_result_t ocf_res_set_resource_types(ocf_resource_s resource, const char **resource_types, uint8_t types_count)
{
	return rt_res_set_resource_types((rt_resource_s *) resource, resource_types, types_count);
}

ocf_result_t ocf_res_is_resource_type_supported(ocf_resource_s resource, const char *resource_type)
{
	return rt_res_is_resource_type_supported((rt_resource_s *) resource, resource_type);
}

ocf_result_t ocf_res_set_resource_protocol(ocf_resource_s resource, ocf_protocol_t scheme)
{
	return rt_res_set_resource_protocol((rt_resource_s *) resource, scheme);
}

ocf_result_t ocf_res_get_resource_protocol(ocf_resource_s resource, uint8_t *scheme)
{
	return rt_res_get_resource_protocol((rt_resource_s *) resource, scheme);
}

ocf_resource_s ocf_res_new_resource(const char *href)
{
	return (ocf_resource_s) rt_res_new_resource(href);
}

void ocf_res_delete_resource(ocf_resource_s resource)
{
	rt_res_delete_resource((rt_resource_s *) resource);
}

void ocf_res_set_request_handler(ocf_resource_s resource, ocf_method_t method, ocf_request_cb callback)
{
	rt_res_set_request_handler((rt_resource_s *) resource, method, callback);
}

ocf_result_t ocf_res_set_discoverable(ocf_resource_s resource, bool value)
{
	return rt_res_set_discoverable((rt_resource_s *) resource, value);
}

bool ocf_res_is_discoverable(ocf_resource_s resource)
{
	return rt_res_is_discoverable((rt_resource_s *) resource);
}

ocf_result_t ocf_res_set_observable(ocf_resource_s resource, bool value)
{
	return rt_res_set_observable((rt_resource_s *) resource, value);
}

bool ocf_res_is_observable(ocf_resource_s resource)
{
	return rt_res_is_observable((rt_resource_s *) resource);
}

ocf_result_t ocf_res_set_secure(ocf_resource_s resource, bool value)
{
	return rt_res_set_secure((rt_resource_s *) resource, value);
}

bool ocf_res_is_secure(ocf_resource_s resource)
{
	return rt_res_is_secure((rt_resource_s *) resource);
}

ocf_result_t ocf_res_register_resource(ocf_resource_s resource)
{
	return rt_res_register_resource((rt_resource_s *) resource);
}

ocf_result_t ocf_res_add_if_rt_rep(ocf_rep_encoder_s main_map, ocf_resource_s resource)
{
	return rt_res_add_if_rt_rep((rt_rep_encoder_s *) main_map, (rt_resource_s *) resource);
}

ocf_result_t ocf_core_add_oic_d_type(const char **device_types, uint8_t device_types_count)
{
	return rt_core_add_oic_d_type(device_types, device_types_count);
}

ocf_result_t ocf_sec_register_ps_handler(ocf_persistent_storage_handler_s *ps_doxm, ocf_persistent_storage_handler_s *ps_pstat, ocf_persistent_storage_handler_s *ps_cred, ocf_persistent_storage_handler_s *ps_acl2)
{
	return rt_sec_register_ps_handler((rt_persistent_storage_handler_s *) ps_doxm, (rt_persistent_storage_handler_s *) ps_pstat, (rt_persistent_storage_handler_s *) ps_cred, (rt_persistent_storage_handler_s *) ps_acl2);
}

ocf_result_t ocf_res_add_link_item(ocf_resource_s rsc_parent, ocf_resource_s rsc_child)
{
	return rt_res_add_link_item((rt_resource_s *) rsc_parent, (rt_resource_s *) rsc_child);
}

ocf_result_t ocf_res_remove_link_item(ocf_resource_s rsc_parent, ocf_resource_s rsc_child)
{
	return rt_res_remove_link_item((rt_resource_s *) rsc_parent, (rt_resource_s *) rsc_child);
}
