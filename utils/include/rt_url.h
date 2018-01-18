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

#ifndef __IOTIVITY_RT_PARSER_H
#define __IOTIVITY_RT_PARSER_H

#include <stdbool.h>
#include <string.h>
#include "rt_mem.h"
#include "ocf_types.h"			// TODO: only need query

typedef enum {
	HOST_IPV4,
	HOST_IPV6,
	HOST_DOMAIN
} rt_host_type_t;

typedef struct _url_field {
	rt_host_type_t host_type;
	char *href;
	char *schema;
	char *username;
	char *password;
	char *host;
	char *port;
	char *path;
	ocf_query_list_s query_list;
	char *fragment;
} rt_url_field_s;

#ifdef __cplusplus
extern "C" {
#endif

void rt_parse_query(ocf_query_list_s *list, char *query, uint16_t len);

rt_url_field_s *rt_url_parse(const char *str);

void rt_query_free(ocf_query_list_s *query_list);

void rt_url_free(rt_url_field_s *url);

void rt_url_field_print(rt_url_field_s *url);

#ifdef __cplusplus
}
#endif
#endif							/* __IOTIVITY_RT_PARSER_H */
