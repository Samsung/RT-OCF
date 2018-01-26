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

#ifndef __RT_OCF_CORE_H
#define __RT_OCF_CORE_H

#include "ocf_types.h"
#include "rt_resources.h"

#define	DISCOVERY_RES_TYPE_DEFAULT "oic.wk.res"
#define	DISCOVERY_RES_TYPE_PLATFORM "oic.wk.p"
#define	DISCOVERY_RES_TYPE_DEVICE "oic.wk.d"
#define	DISCOVERY_RES_TYPE_INTROSPECTION "oic.wk.introspection"

#define	DEVICE_PROPERTY_SPEC_VER "ocf.1.0.0"

ocf_result_t rt_core_res_init(const char *manufacturer_name, const char *data_model_ver);
ocf_result_t rt_core_res_terminate(void);

void rt_core_res_discovery_handler(const rt_request_s *request);

rt_resource_s *rt_core_make_oic_p(const char *manufacturer_name);
rt_resource_s *rt_core_make_oic_d(const char *data_model_ver);
rt_resource_s *rt_core_make_introspection(const char *introspection_url);

ocf_result_t rt_core_remove_oic_p(void);
ocf_result_t rt_core_remove_oic_d(void);
ocf_result_t rt_core_remove_introspection(void);

ocf_result_t rt_core_set_oic_d_name_opt(const char *value);
ocf_result_t rt_core_add_oic_d_type(const char **device_types, uint8_t device_types_count);

#endif							/* __RT_OCF_CORE_H */
