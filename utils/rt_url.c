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

#include "ocf_types.h"
#include "rt_url.h"
#include "rt_logger.h"
#include "rt_utils.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define TAG "RT_URL"
static char *str_hosttype[] = { "host ipv4", "host ipv6", "host domain", NULL };

char *rt_strndup(const char *str, int n)
{
	// RT_LOG_D(TAG, "str = %s", str);
	char *dst;
	RT_VERIFY_NON_NULL_RET(str, TAG, "str is NULL", NULL);

	if (n < 0) {
		n = strlen(str);
	}
	if (n == 0) {
		return NULL;
	}
	if ((dst = (char *)rt_mem_alloc(n + 1)) == NULL) {
		return NULL;
	}
	// RT_LOG_D(TAG, "dst_len = %d", n);
	memcpy(dst, str, n);
	dst[n] = 0;
	return dst;
}

static int host_is_ipv4(char *str)
{
	RT_VERIFY_NON_NULL_RET(str, TAG, "str is NULL", 0);
	while (*str) {
		if ((*str >= '0' && *str <= '9') || *str == '.') {
			str++;
		} else {
			return 0;
		}
	}
	return 1;
}

void rt_parse_query(ocf_query_list_s *list, char *query, uint16_t len)
{
	char *chr;
	RT_VERIFY_NON_NULL_VOID(list, TAG, "query list is NULL");
	RT_VERIFY_NON_NULL_VOID(query, TAG, "query is NULL");

	char *origin_query = rt_mem_alloc(len + 1);
	RT_VERIFY_NON_NULL_VOID(origin_query, TAG, "origin_query");
	memcpy(origin_query, query, len);
	origin_query[len] = '\0';
	query = origin_query;

	chr = strchr(query, '=');
	while (chr) {
		if (list->query) {
			list->query = (ocf_query_s *) rt_mem_realloc(list->query, (list->query_num + 1) * sizeof(*list->query));
		} else {
			list->query = (ocf_query_s *) rt_mem_alloc(sizeof(*list->query));
		}
		RT_VERIFY_NON_NULL_VOID(list->query, TAG, "list->query");
		list->query[list->query_num].name = rt_strndup(query, chr - query);
		query = chr + 1;
		chr = strchr(query, '&');
		if (chr) {
			list->query[list->query_num].value = rt_strndup(query, chr - query);
			list->query_num++;
			query = chr + 1;
			chr = strchr(query, '=');
		} else {
			list->query[list->query_num].value = rt_strndup(query, -1);
			list->query_num++;
			break;
		}
	}
	rt_mem_free(origin_query);
}

rt_url_field_s *rt_url_parse(const char *str)
{
	const char *pch;
	char *query;
	rt_url_field_s *url;
	query = NULL;

	RT_VERIFY_NON_NULL_RET(str, TAG, "str is NULL", NULL);

	if ((url = (rt_url_field_s *) rt_mem_alloc(sizeof(rt_url_field_s))) == NULL) {
		return NULL;
	}
	memset(url, 0, sizeof(rt_url_field_s));

	url->href = rt_strndup(str, -1);
	pch = strchr(str, ':');		/* parse schema */
	if (pch && pch[1] == '/' && pch[2] == '/') {
		url->schema = rt_strndup(str, pch - str);
		str = pch + 3;
	} else {
		goto __fail;
	}
	pch = strchr(str, '@');		/* parse user info */
	if (pch) {
		pch = strchr(str, ':');
		if (pch) {
			url->username = rt_strndup(str, pch - str);
			str = pch + 1;
			pch = strchr(str, '@');
			if (pch) {
				url->password = rt_strndup(str, pch - str);
				str = pch + 1;
			} else {
				goto __fail;
			}
		} else {
			goto __fail;
		}
	}
	if (str[0] == '[') {		/* parse host info */
		str++;
		pch = strchr(str, ']');
		if (pch) {
			url->host = rt_strndup(str, pch - str);
			str = pch + 1;
			if (str[0] == ':') {
				str++;
				pch = strchr(str, '/');
				if (pch) {
					url->port = rt_strndup(str, pch - str);
					str = pch + 1;
				} else {
					url->port = rt_strndup(str, -1);
					str = str + strlen(str);
				}
			}
			url->host_type = HOST_IPV6;
		} else {
			goto __fail;
		}
	} else {
		const char *pch_slash;
		pch = strchr(str, ':');
		pch_slash = strchr(str, '/');
		if (pch && (!pch_slash || (pch_slash && pch < pch_slash))) {
			url->host = rt_strndup(str, pch - str);
			str = pch + 1;
			pch = strchr(str, '/');
			if (pch) {
				url->port = rt_strndup(str, pch - str);
				str = pch + 1;
			} else {
				url->port = rt_strndup(str, -1);
				str = str + strlen(str);
			}
		} else {
			pch = strchr(str, '/');
			if (pch) {
				url->host = rt_strndup(str, pch - str);
				str = pch + 1;
			} else {
				url->host = rt_strndup(str, -1);
				str = str + strlen(str);
			}
		}
		url->host_type = host_is_ipv4(url->host) ? HOST_IPV4 : HOST_DOMAIN;
	}
	if (str[0]) {				/* parse path, query and fragment */
		pch = strchr(str, '?');
		if (pch) {
			url->path = rt_strndup(str, pch - str);
			str = pch + 1;
			pch = strchr(str, '#');
			if (pch) {
				query = rt_strndup(str, pch - str);
				str = pch + 1;
				url->fragment = rt_strndup(str, -1);
			} else {
				query = rt_strndup(str, -1);
				str = str + strlen(str);
			}
			rt_parse_query(&url->query_list, query, strlen(query));
			rt_mem_free(query);
		} else {
			pch = strchr(str, '#');
			if (pch) {
				url->path = rt_strndup(str, pch - str);
				str = pch + 1;
				url->fragment = rt_strndup(str, -1);
				str = str + strlen(str);
			} else {
				url->path = rt_strndup(str, -1);
				str = str + strlen(str);
			}
		}
	}

	return url;

__fail:
	rt_url_free(url);
	return NULL;
}

void rt_query_free(ocf_query_list_s *query_list)
{
	RT_VERIFY_NON_NULL_VOID(query_list, TAG, "query_list is null");
	if (query_list->query) {
		int i;
		for (i = 0; i < query_list->query_num; i++) {
			rt_mem_free(query_list->query[i].name);
			rt_mem_free(query_list->query[i].value);
		}
		rt_mem_free(query_list->query);
	}
}

void rt_url_free(rt_url_field_s *url)
{
	if (!url) {
		return;
	}
	if (url->href) {
		rt_mem_free(url->href);
	}
	if (url->schema) {
		rt_mem_free(url->schema);
	}
	if (url->username) {
		rt_mem_free(url->username);
	}
	if (url->password) {
		rt_mem_free(url->password);
	}
	if (url->host) {
		rt_mem_free(url->host);
	}
	if (url->port) {
		rt_mem_free(url->port);
	}
	if (url->path) {
		rt_mem_free(url->path);
	}

	rt_query_free(&url->query_list);

	if (url->fragment) {
		rt_mem_free(url->fragment);
	}
	rt_mem_free(url);
}

void rt_url_field_print(rt_url_field_s *url)
{
	if (!url) {
		return;
	}
	RT_LOG_D(TAG, "url field:");
	RT_LOG_D(TAG, "  - href:     '%s'", url->href);
	RT_LOG_D(TAG, "  - schema:   '%s'", url->schema);
	if (url->username) {
		RT_LOG_D(TAG, "  - username: '%s'", url->username);
	}
	if (url->password) {
		RT_LOG_D(TAG, "  - password: '%s'", url->password);
	}
	RT_LOG_D(TAG, "  - host:     '%s' (%s)", url->host, str_hosttype[url->host_type]);
	if (url->port) {
		RT_LOG_D(TAG, "  - port:     '%s'", url->port);
	}
	if (url->path) {
		RT_LOG_D(TAG, "  - path:     '%s'", url->path);
	}
	if (url->query_list.query_num > 0) {
		int i;
		RT_LOG_D(TAG, "  - query");
		for (i = 0; i < url->query_list.query_num; i++) {
			RT_LOG_D(TAG, "    * %s : %s", url->query_list.query[i].name, url->query_list.query[i].value);
		}
	}
	if (url->fragment) {
		RT_LOG_D(TAG, "  - fragment: '%s'", url->fragment);
	}
}
