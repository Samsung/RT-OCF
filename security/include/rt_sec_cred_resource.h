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

#ifndef __RT_OCF_SEC_CRED_RESOURCE_H
#define __RT_OCF_SEC_CRED_RESOURCE_H

#include "ocf_types.h"
#include "rt_uuid.h"
#include "rt_utils.h"
#include "rt_list.h"
//TOD0 : remove #include "rt_rep.h" after test
#include "rt_rep.h"

typedef enum {
	NO_SECURITY_MODE = 0x0,
	SYMMETRIC_PAIR_WISE_KEY = (0x1 << 0),
	SYMMETRIC_GROUP_KEY = (0x1 << 1),
	ASYMMETRIC_SIGNING_KEY = (0x1 << 2),
	ASYMMETRIC_SIGNED_KEY_WITH_CERTIFICATE = (0x1 << 3),
	PIN_PASSWORD = (0x1 << 4),
	ASYMMETRIC_ENCRYPTION_KEY = (0x1 << 5),
} rt_sec_cred_type_t;

typedef enum {
	RT_ENCODING_RAW = 0,
	RT_ENCODING_BASE64 = 1,
	RT_ENCODING_PEM = 2,
	RT_ENCODING_DER = 3,
	RT_ENCODING_MAX
} rt_encoding_type_t;

typedef struct {
	uint8_t *data;
	size_t len;
	rt_encoding_type_t encoding;
	bool revstat;
} rt_sec_opt_s;

typedef struct {
	uint8_t *data;
	size_t len;
	rt_encoding_type_t encoding;
} rt_sec_key_s;

typedef struct {
	uint16_t cred_id;
	rt_uuid_t subject_id;
	rt_sec_cred_type_t cred_type;
	rt_sec_key_s public_data;
	char *cred_usage;
	rt_sec_opt_s optional_data;
	rt_sec_key_s private_data;
	char *period;
	rt_node_s node;
} rt_sec_creds_s;

typedef struct {
	rt_list_s creds;
	rt_uuid_t rowner_id;
	uint16_t max_cred_id;
} rt_sec_credential_s;

ocf_result_t rt_sec_cred_init(void);
ocf_result_t rt_sec_cred_get_by_subjectuuid(const rt_uuid_t uuid, rt_sec_creds_s **cred);
ocf_result_t rt_sec_cred_get_psk(const uint8_t *uuid, size_t uuid_len, uint8_t *psk, size_t *psk_len);

//TODO : Change below func to static after testing
rt_rep_encoder_s *rt_convert_cred_to_payload(rt_sec_credential_s *cred, bool response);

#endif
