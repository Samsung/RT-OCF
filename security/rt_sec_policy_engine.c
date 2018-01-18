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

#include "rt_sec_policy_engine.h"
#include "rt_sec_acl2_resource.h"
#include "rt_sec_types.h"
#include "rt_data_handler.h"
#include "rt_utils.h"
#include "ocf_types.h"
#include "rt_mem.h"

#define TAG "RT_SEC_PE"

static uint16_t rt_sec_pe_convert_permission_from_method(uint8_t method)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	uint16_t permission = 0;
	switch (method) {
	case OCF_GET:
		permission = (uint16_t) OCF_PERMISSION_READ;
		break;
	case OCF_POST:
		permission = (uint16_t) OCF_PERMISSION_WRITE;
		break;
	case OCF_PUT:
		permission = (uint16_t) OCF_PERMISSION_CREATE;
		break;
	case OCF_DELETE:
		permission = (uint16_t) OCF_PERMISSION_DELETE;
		break;
	default:
		RT_LOG_E(TAG, "Invalid Method");
		break;
	}
	RT_LOG_D(TAG, "%s OUT", __func__);
	return permission;
}

bool rt_sec_pe_check_permission(rt_request_s *request, uint8_t method)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	uint16_t perm = rt_sec_pe_convert_permission_from_method(method);
	if (0 == perm) {
		RT_LOG_E(TAG, "Invalid Method");
		return false;
	}
	// checking permission by conntype.
	rt_sec_conn_type_t conntype;
	if (request->endpoint->flags & OCF_SECURE) {
		conntype = AUTH_CRYPT;
	} else {
		conntype = ANON_CLEAR;
	}

	if (true == rt_sec_acl2_check_permission_by_conntype(conntype, request->data->uri_path, perm)) {
		RT_LOG_D(TAG, "ACCESS GRANTED by Conntype!!");
		RT_LOG_D(TAG, "%s OUT", __func__);
		return true;
	}

	if (true == rt_sec_acl2_check_permission_by_subjectuuid((uint8_t *)request->endpoint->peerId, request->data->uri_path, perm)) {
		RT_LOG_D(TAG, "ACCESS GRANTED by Subjectuuid!!");
		RT_LOG_D(TAG, "%s OUT", __func__);
		return true;
	}

	RT_LOG_D(TAG, "%s OUT", __func__);
	return false;
}
