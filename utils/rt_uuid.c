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

#include "rt_uuid.h"
#include "rt_logger.h"
#include "rt_string.h"
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/in.h>

#define TAG "RT_UUID"

static void get_mac_addr(uint8_t *mac_addr)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	struct ifreq ifr;
	struct ifconf ifc;
	char buf[1024];
	int success = 0;

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) {			/* handle error */
		RT_LOG_E(TAG, "socket open failed");
		return;
	}

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {	/* handle error */
		RT_LOG_E(TAG, "ioctl[SIOCGIFCONF] setup error");
		close(sock);
		return;
	}

	struct ifreq *it = ifc.ifc_req;
	const struct ifreq *const end = it + (ifc.ifc_len / sizeof(struct ifreq));

	for (; it != end; ++it) {
		rt_strncpy(ifr.ifr_name, it->ifr_name, IFNAMSIZ);
		if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
			if (!(ifr.ifr_flags & IFF_LOOPBACK)) {	// don't count loopback
				if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
					success = 1;
					break;
				}
			}
		} else {				/* handle error */
			RT_LOG_E(TAG, "ioctl[SIOCGIFFLAGS] setup error");
		}
	}

	if (success) {
		memcpy(mac_addr, ifr.ifr_hwaddr.sa_data, 6);
	}
	close(sock);

	RT_LOG_D(TAG, "%s OUT", __func__);
}

ocf_result_t rt_uuid_generate(rt_uuid_t uuid)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	int i;
	uint16_t seed = 0;
	uint8_t mac[6];

	get_mac_addr(mac);

	for (i = 0; i < 6; ++i) {
		seed += mac[i];
	}

	// Set seed for static uuid
	srand(seed);
	rt_random_rand_to_buffer(uuid, 16);
	// Reset seed for random value
	srand(rt_clock_time());
	RT_LOG_D(TAG, "%s OUT", __func__);
	return OCF_OK;
}

static int hex2num(char c)
{
	if (c >= '0' && c <= '9') {
		return c - '0';
	}
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	}
	return -1;
}

static int hex2byte(const char *hex)
{
	int a, b;
	a = hex2num(*hex++);
	if (a < 0) {
		return -1;
	}
	b = hex2num(*hex++);
	if (b < 0) {
		return -1;
	}
	return (a << 4) | b;
}

static int hexstr2bin(const char *hex, rt_uuid_t buf, size_t len)
{
	size_t i;
	int a;
	const char *ipos = hex;
	uint8_t *opos = buf;

	for (i = 0; i < len; i++) {
		a = hex2byte(ipos);
		if (a < 0) {
			return -1;
		}
		*opos++ = a;
		ipos += 2;
	}
	return 0;
}

ocf_result_t rt_uuid_str2uuid(const char *str, rt_uuid_t bin)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	const char *pos;
	uint8_t *opos;

	memset(bin, 0, RT_UUID_LEN);

	pos = str;
	opos = bin;

	if (hexstr2bin(pos, opos, 4)) {
		return OCF_ERROR;
	}
	pos += 8;
	opos += 4;

	if (*pos++ != '-' || hexstr2bin(pos, opos, 2)) {
		return OCF_ERROR;
	}
	pos += 4;
	opos += 2;

	if (*pos++ != '-' || hexstr2bin(pos, opos, 2)) {
		return OCF_ERROR;
	}
	pos += 4;
	opos += 2;

	if (*pos++ != '-' || hexstr2bin(pos, opos, 2)) {
		return OCF_ERROR;
	}
	pos += 4;
	opos += 2;

	if (*pos++ != '-' || hexstr2bin(pos, opos, 6)) {
		return OCF_ERROR;
	}
	RT_LOG_D(TAG, "%s OUT", __func__);
	return OCF_OK;
}

ocf_result_t rt_uuid_uuid2str(const rt_uuid_t bin, char *str, size_t max_len)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	int len;
	len = snprintf(str, max_len, "%02x%02x%02x%02x-%02x%02x-%02x%02x-" "%02x%02x-%02x%02x%02x%02x%02x%02x", bin[0], bin[1], bin[2], bin[3], bin[4], bin[5], bin[6], bin[7], bin[8], bin[9], bin[10], bin[11], bin[12], bin[13], bin[14], bin[15]);

	if (len + 1 > max_len) {
		return OCF_INVALID_PARAM;
	}
	RT_LOG_D(TAG, "%s OUT", __func__);
	return OCF_OK;
}

bool rt_uuid_is_empty(rt_uuid_t uuid)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	int i;
	for (i = 0; i < RT_UUID_LEN; ++i) {
		if (uuid[i] != 0) {
			return false;
		}
	}
	RT_LOG_D(TAG, "%s OUT", __func__);
	return true;
}

bool rt_uuid_is_astrict(rt_uuid_t uuid)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	int i;
	if (uuid[0] != 0x2a) {
		return false;
	}
	for (i = 1; i < RT_UUID_LEN; ++i) {
		if (uuid[i] != 0) {
			return false;
		}
	}

	RT_LOG_D(TAG, "%s OUT", __func__);
	return true;
}
