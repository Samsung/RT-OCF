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

#ifndef __RT_OCF_SEC_DOXM_RESOURCE_H
#define __RT_OCF_SEC_DOXM_RESOURCE_H

#include "rt_rep.h"
#include "rt_uuid.h"

typedef enum {
	OCF_JUST_WORKS = 0,
	OCF_RANDOM_PIN = 1,
	OCF_MFG_CERT = 2,
	OCF_SELF = 4
} rt_doxm_type_t;

typedef struct {
	int *oxm;
	uint16_t len;
} rt_oxms_s;

typedef struct {
	int sct;
	bool owned;
	int oxmsel;
	rt_oxms_s oxms;
	rt_uuid_t deviceuuid;
	rt_uuid_t devowneruuid;
	rt_uuid_t rowneruuid;
} rt_sec_doxm_s;

ocf_result_t rt_sec_doxm_init(void);
ocf_result_t rt_sec_doxm_terminate(void);
ocf_result_t rt_sec_doxm_get_deviceuuid(char *deviceuuid);
ocf_result_t rt_sec_doxm_get_devowneruuid(char *devowneruuid);
void rt_sec_doxm_get_deviceuuid_byte(rt_uuid_t deviceuuid);

//TODO : Change below func to static after testing
rt_rep_encoder_s *rt_convert_doxm_to_payload(rt_sec_doxm_s *doxm, bool is_response);

#endif
