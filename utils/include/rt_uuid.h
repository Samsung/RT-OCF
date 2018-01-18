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

#ifndef __IOTIVITY_RT_UUID_H
#define __IOTIVITY_RT_UUID_H

#include "ocf_types.h"

#define RT_UUID_STR_LEN 37
#define RT_UUID_LEN 16

typedef uint8_t rt_uuid_t[RT_UUID_LEN];
typedef char rt_uuid_str_t[RT_UUID_STR_LEN];

ocf_result_t rt_uuid_generate(rt_uuid_t uuid);
ocf_result_t rt_uuid_str2uuid(const char *str, rt_uuid_t bin);
ocf_result_t rt_uuid_uuid2str(const rt_uuid_t bin, char *str, size_t max_len);
bool rt_uuid_is_empty(rt_uuid_t uuid);
bool rt_uuid_is_astrict(rt_uuid_t uuid);

#endif
