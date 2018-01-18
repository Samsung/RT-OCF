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

#ifndef __IOTIVITY_RT_SEC_ACL2_RESOURCE_H
#define __IOTIVITY_RT_SEC_ACL2_RESOURCE_H

#include "ocf_types.h"
#include "rt_uuid.h"
#include "rt_list.h"

typedef enum {
	rt_sec_ace_uuid_subject = 0,
	rt_sec_ace_role_subject,
	rt_sec_ace_conntype_subject
} rt_sec_ace_subject_type_t;

typedef enum {
	AUTH_CRYPT,
	ANON_CLEAR
} rt_sec_conn_type_t;

typedef enum {
	RT_NO_WILDCARD = 0,
	RT_ALL_DISCOVERABLE,
	RT_ALL_NON_DISCOVERABLE,
	RT_ALL_RESOURCES
} rt_sec_ace_wildcard_t;

typedef struct rt_sec_ace_resource_s {
	char *href;
	char **res_type;
	uint16_t res_type_len;
	char **interface;
	uint16_t interface_len;
	rt_sec_ace_wildcard_t wc;
	struct rt_sec_ace_resource_s *next;
} rt_sec_ace_resource_s;

typedef struct {
	rt_sec_ace_subject_type_t subject_type;
	union {
		rt_uuid_t subject_uuid;
		rt_sec_conn_type_t subject_conn;
	};
	rt_sec_ace_resource_s *resources;
	uint16_t permission;
	rt_node_s node;
} rt_sec_ace_s;

typedef struct {
	rt_list_s aces;
	rt_uuid_t rowner_id;
} rt_sec_acl2_s;

ocf_result_t rt_sec_acl2_init(void);
ocf_result_t rt_sec_acl2_terminate(void);

rt_rep_encoder_s *rt_convert_acl2_to_payload(rt_sec_acl2_s *cred, bool is_response);
ocf_result_t rt_convert_payload_to_acl2(rt_rep_decoder_s *rep, rt_sec_acl2_s *out, bool is_request);
bool rt_sec_acl2_check_permission_by_conntype(rt_sec_conn_type_t conntype, const char *href, uint16_t perm);
bool rt_sec_acl2_check_permission_by_subjectuuid(rt_uuid_t subject, const char *href, uint16_t perm);

#endif
