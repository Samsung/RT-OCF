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

#ifndef __RT_OCF_COLLECTION_H
#define __RT_OCF_COLLECTION_H

#include "ocf_resources.h"

ocf_result_t rt_res_add_link_item(rt_resource_s *rsc_parent, rt_resource_s *rsc_child);
ocf_result_t rt_res_remove_link_item(rt_resource_s *rsc_parent, rt_resource_s *rsc_child);
ocf_result_t rt_res_remove_links(rt_resource_s *parent);

//ocf_result_t rt_res_init_links(void);
//ocf_result_t rt_res_terminate_links(void);

#endif							/* __RT_OCF_COLLECTION_H */
