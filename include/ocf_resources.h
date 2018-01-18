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

#ifndef OCFRESOURCES_H_
#define OCFRESOURCES_H_

#include "ocf_types.h"
#include "ocf_rep.h"

#ifdef __cplusplus
extern "C" {
#endif							// __cplusplus

typedef struct rt_resource_s *ocf_resource_s;
typedef struct _rt_request_s rt_request_s;
typedef struct rt_request_s *ocf_request_s;

typedef struct _rt_resource_type_list_s {
	char *resource_type;
	struct _rt_resource_type_list_s *next;
} rt_resource_type_list_s;  //TODO: move to another code space.

typedef void (*ocf_request_cb)(ocf_request_s request, ocf_rep_decoder_s payload);

ocf_result_t ocf_res_set_base_interface(ocf_resource_s resource, ocf_interface_mask_t interfaces);
ocf_result_t ocf_res_get_base_interface(ocf_resource_s resource, uint8_t *interface);
ocf_result_t ocf_res_is_interface_supported(ocf_resource_s resource, ocf_interface_mask_t);
ocf_result_t ocf_res_set_interface(ocf_resource_s resource, ocf_interface_mask_t);
ocf_result_t ocf_res_get_interface_string_value(uint8_t interface, char *interface_str);
ocf_interface_mask_t ocf_res_get_interface_enum_value(char *interface_str);

ocf_result_t ocf_res_set_resource_types(ocf_resource_s resource, const char **resource_types, uint8_t types_count);
ocf_result_t ocf_res_is_resource_type_supported(ocf_resource_s resource, const char *resource_type);

ocf_result_t ocf_res_set_resource_protocol(ocf_resource_s resource, ocf_protocol_t scheme);
ocf_result_t ocf_res_get_resource_protocol(ocf_resource_s resource, uint8_t *scheme);

ocf_resource_s ocf_res_new_resource(const char *href);
void ocf_res_delete_resource(ocf_resource_s resource);
ocf_result_t ocf_res_register_resource(ocf_resource_s resource);

void ocf_res_set_request_handler(ocf_resource_s resource, ocf_method_t method, ocf_request_cb callback);

ocf_result_t ocf_res_set_discoverable(ocf_resource_s resource, bool value);
bool ocf_res_is_discoverable(ocf_resource_s resource);
ocf_result_t ocf_res_set_observable(ocf_resource_s resource, bool value);
bool ocf_res_is_observable(ocf_resource_s resource);
ocf_result_t ocf_res_set_secure(ocf_resource_s resource, bool value);
bool ocf_res_is_secure(ocf_resource_s resource);

ocf_result_t ocf_sec_register_ps_handler(ocf_persistent_storage_handler_s *ps_doxm, ocf_persistent_storage_handler_s *ps_pstat, ocf_persistent_storage_handler_s *ps_cred, ocf_persistent_storage_handler_s *ps_acl2);

ocf_result_t ocf_res_add_link_item(ocf_resource_s rsc_parent, ocf_resource_s rsc_child);
ocf_result_t ocf_res_remove_link_item(ocf_resource_s rsc_parent, ocf_resource_s rsc_child);

#ifdef __cplusplus
}
#endif							// __cplusplus
#endif
