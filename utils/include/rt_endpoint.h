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

#ifndef __RT_OCF_ENDPOINT_H_
#define __RT_OCF_ENDPOINT_H_

#include <stdint.h>
#include "ocf_types.h"
#include "rt_url.h"
#include "rt_logger.h"

#ifdef __cplusplus
extern "C" {
#endif							// __cplusplus

ocf_result_t rt_endpoint_set(ocf_endpoint_s *endpoint, const char *ip, uint16_t port, ocf_transport_flags_t flags);
bool rt_endpoint_is_equal(const ocf_endpoint_s *endpoint1, const ocf_endpoint_s *endpoint2);
void rt_endpoint_get_addr_str(const ocf_endpoint_s *endpoint, char *buf, size_t size);
void rt_endpoint_log(ocf_log_level_t level, const char *tag, const ocf_endpoint_s *endpoint);
ocf_result_t rt_endpoint_get_flags(rt_url_field_s *parse_url, ocf_transport_flags_t *flags);

#ifdef __cplusplus
}
#endif							// __cplusplus
#endif							/* __RT_OCF_ENDPOINT_H_ */
