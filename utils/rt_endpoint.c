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

#include <sys/socket.h>
#include <string.h>
#include "rt_utils.h"
#include "rt_endpoint.h"
#include "rt_mem.h"
#include "rt_url.h"

#define TAG "RT_ENDPOINT"
#define IPV4_LENGTH 4
#define IPV6_LENGTH 16

ocf_result_t rt_endpoint_set(ocf_endpoint_s *endpoint, const char *ip, uint16_t port, ocf_transport_flags_t flags)
{
	RT_VERIFY_NON_NULL_RET(endpoint, TAG, "endpoint is null", OCF_INVALID_PARAM);

	if (flags & OCF_IPV6) {
		return OCF_INVALID_PARAM;
	}

	memset(endpoint, 0, sizeof(ocf_endpoint_s));

	if (flags & OCF_IPV4) {
		inet_pton(AF_INET, ip, &(endpoint->addr[0]));
	}

	endpoint->port = port;
	endpoint->flags = flags;

	return OCF_OK;
}

static bool is_equal_ip(const ocf_endpoint_s *endpoint1, const ocf_endpoint_s *endpoint2)
{

	size_t len = 0;

	if ((endpoint1->flags & OCF_IPV4) && (endpoint2->flags & OCF_IPV4)) {
		len = IPV4_LENGTH;
	} else if ((endpoint1->flags & OCF_IPV6) && (endpoint2->flags & OCF_IPV6)) {
		len = IPV6_LENGTH;
	} else {
		return false;
	}

	if (memcmp(endpoint1->addr, endpoint2->addr, len)) {
		return false;
	}

	return true;
}

static bool is_equal_port(const ocf_endpoint_s *endpoint1, const ocf_endpoint_s *endpoint2)
{
	if (endpoint1->port != endpoint2->port) {
		return false;
	}

	return true;
}

bool rt_endpoint_is_equal(const ocf_endpoint_s *endpoint1, const ocf_endpoint_s *endpoint2)
{
	RT_VERIFY_NON_NULL_RET(endpoint1, TAG, "endpoint1 is null", false);
	RT_VERIFY_NON_NULL_RET(endpoint2, TAG, "endpoint2 is null", false);

	if (!is_equal_ip(endpoint1, endpoint2)) {
		return false;
	}
	if (!is_equal_port(endpoint1, endpoint2)) {
		return false;
	}

	return true;
}

void rt_endpoint_get_addr_str(const ocf_endpoint_s *endpoint, char *buf, size_t size)
{

	RT_VERIFY_NON_NULL_VOID(endpoint, TAG, "endpoint is NULL");
	RT_VERIFY_NON_NULL_VOID(buf, TAG, "buf is NULL");
	inet_ntop(AF_INET, &(endpoint->addr[0]), buf, size);
}

void rt_endpoint_log(ocf_log_level_t level, const char *tag, const ocf_endpoint_s *endpoint)
{
	RT_VERIFY_NON_NULL_VOID(endpoint, tag, "endpoint is null");

	char buf[40];
	rt_endpoint_get_addr_str(endpoint, buf, sizeof(buf));
	RT_LOG(level, tag, "%s:%u", buf, endpoint->port);
	RT_LOG(level, tag, "flags: 0x%x", endpoint->flags);
}

ocf_result_t rt_endpoint_get_flags(rt_url_field_s *parse_url, ocf_transport_flags_t *flags)
{
	// RT_LOG_D(TAG, "%s IN", __func__);
	// rt_url_field_print(parse_url);
	if (0 == strcmp(parse_url->schema, COAP_PREFIX)) {
		*flags |= OCF_UDP;
	} else if (0 == strcmp(parse_url->schema, COAPS_PREFIX)) {
		*flags |= (OCF_UDP | OCF_SECURE);
	} else if (0 == strcmp(parse_url->schema, COAP_TCP_PREFIX)) {
		*flags |= OCF_TCP;
	} else if (0 == strcmp(parse_url->schema, COAPS_TCP_PREFIX)) {
		*flags |= (OCF_TCP | OCF_SECURE);
	} else {
		RT_LOG_D(TAG, "Invalid url : %s OUT", __func__);
		rt_url_free(parse_url);
		return OCF_ERROR;
	}

	if (HOST_IPV4 == parse_url->host_type) {
		*flags |= OCF_IPV4;
	} else if (HOST_IPV6 == parse_url->host_type) {
		*flags |= OCF_IPV6;
	} else {
		RT_LOG_D(TAG, "Invalid host type : %s OUT", __func__);
		return OCF_ERROR;
	}

	// RT_LOG_D(TAG, "%s OUT", __func__);
	return OCF_OK;
}
