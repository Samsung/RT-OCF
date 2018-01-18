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

#ifndef __IOTIVITY_RT_SEC_PSTAT_RESOURCE_H
#define __IOTIVITY_RT_SEC_PSTAT_RESOURCE_H

#include "ocf_types.h"
#include "rt_uuid.h"

// {
//     "dos": {
//         "s": 1,
//         "p": false
//     },
//     "isop": false,
//     "cm": 2,
//     "tm": 0,
//     "om": 4,
//     "sm": 4,
//     "rowneruuid": "11111111-1111-1111-1111-111111111111"
// }

typedef enum {
	MULTIPLE_SERVICE_SERVER_DRIVEN = (0x1 << 0),
	SINGLE_SERVICE_SERVER_DRIVEN = (0x1 << 1),
	SINGLE_SERVICE_CLIENT_DRIVEN = (0x1 << 2)
} rt_sec_dpom_t;

typedef enum {
	DOS_RESET = 0,
	DOS_RFOTM,
	DOS_RFPRO,
	DOS_RFNOP,
	DOS_SRESET,
	DOS_STATE_COUNT
} rt_sec_device_onboarding_state_t;

typedef struct OicSecDostype {
	rt_sec_device_onboarding_state_t state;
	bool pending;
} rt_sec_dos_s;

typedef struct rt_sec_pstat_s {
	rt_sec_dos_s dos;
	bool isop;
	uint8_t cm;
	uint8_t tm;
	uint8_t om;
	uint8_t sm;
	rt_uuid_t rowner_id;
} rt_sec_pstat_s;

ocf_result_t rt_sec_pstat_init(void);
ocf_result_t rt_sec_pstat_terminate(void);

rt_rep_encoder_s *rt_convert_pstat_to_payload(rt_sec_pstat_s *pstat, bool is_response);
ocf_result_t rt_convert_payload_to_pstat(rt_rep_decoder_s *rep, rt_sec_pstat_s *out, bool is_request);

#endif
