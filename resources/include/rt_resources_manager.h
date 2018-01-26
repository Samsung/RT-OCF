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

#ifndef __RT_OCF_RESOURCES_MANAGER_H
#define __RT_OCF_RESOURCES_MANAGER_H

#include "ocf_types.h"

typedef struct _rt_resource_s rt_resource_s;
typedef struct _rt_list rt_list_s;

ocf_result_t rt_resource_manager_init(const char *manufacturer_name, const char *data_model_ver);
ocf_result_t rt_resource_manager_terminate(void);
ocf_result_t rt_res_register_resource(rt_resource_s *resource);
ocf_result_t rt_res_deregister_resource(rt_resource_s *resource);

bool rt_res_is_discoverable(rt_resource_s *resource);
bool rt_res_is_observable(rt_resource_s *resource);
bool rt_res_is_secure(rt_resource_s *resource);
bool rt_res_is_discoverable_by_href(const char *request_href);

rt_resource_s *rt_res_get_resource_by_href(const char *href);
const rt_list_s *rt_res_get_registered_list(void);

#endif
