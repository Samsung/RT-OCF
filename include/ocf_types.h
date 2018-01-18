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

/**
 * @file
 *
 * This file contains the definition, types and APIs for resource(s) be implemented.
 */

#ifndef OCFTYPES_H_
#define OCFTYPES_H_

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus

extern "C" {
#endif							// __cplusplus

//-----------------------------------------------------------------------------
// Defines
//-----------------------------------------------------------------------------

/**
 * Security Configs.
 */
#define OCF_UUID_LENGTH (128/8)

/**
 * Host Mode of Operation.
 */
typedef enum {
	OCF_CLIENT = 0,
	OCF_SERVER,
	OCF_CLIENT_SERVER
} ocf_mode_t;

typedef enum {
	OCF_INTERFACE_DOWN,
	/**< Connection is not available */
	OCF_INTERFACE_UP
	/**< Connection is Available */
} ocf_network_status_t;

//
/**
 * Declares Stack Results & Errors.
 */
typedef enum {
	/** Success status code - START HERE.*/
	OCF_OK = 0,
	OCF_RESOURCE_CREATED,
	OCF_RESOURCE_DELETED,
	OCF_CONTINUE,
	OCF_RESOURCE_CHANGED,
	/** Success status code - END HERE.*/

	/** Error status code - START HERE.*/
	OCF_INVALID_URI = 20,
	OCF_INVALID_QUERY,
	OCF_INVALID_IP,
	OCF_INVALID_PORT,
	OCF_INVALID_CALLBACK,
	OCF_INVALID_METHOD,

	/** Invalid parameter.*/
	OCF_INVALID_PARAM,
	OCF_INVALID_OBSERVE_PARAM,
	OCF_NO_MEMORY,
	OCF_COMM_ERROR,
	OCF_TIMEOUT,
	OCF_ADAPTER_NOT_ENABLED,
	OCF_NOTIMPL,

	/** Resource not found.*/
	OCF_NO_RESOURCE,

	/** e.g: not supported method or interface.*/
	OCF_RESOURCE_ERROR,
	OCF_SLOW_RESOURCE,
	OCF_DUPLICATE_REQUEST,

	/** Resource has no registered observers.*/
	OCF_NO_OBSERVERS,
	OCF_OBSERVER_NOT_FOUND,
	OCF_VIRTUAL_DO_NOT_HANDLE,
	OCF_INVALID_OPTION,

	/** The remote reply contained malformed data.*/
	OCF_MALFORMED_RESPONSE,
	OCF_PERSISTENT_BUFFER_REQUIRED,
	OCF_INVALID_REQUEST_HANDLE,
	OCF_INVALID_DEVICE_INFO,
	OCF_INVALID_JSON,

	/** Request is not authorized by Resource Server. */
	OCF_UNAUTHORIZED_REQ,
	OCF_TOO_LARGE_REQ,

	/** Error Type in Memory Management */
	OCF_MEM_FULL,

	/** Error Type in Function initialization */
	OCF_ALREADY_INIT,
	OCF_NOT_INITIALIZE,

	/** Error code from PDM */
	OCF_PDM_IS_NOT_INITIALIZED,
	OCF_DUPLICATE_UUID,
	OCF_INCONSISTENT_DB,
	OCF_SVR_DB_NOT_EXIST,

	/**
	 * Error code from OTM
	 * This error is pushed from DTLS interface when handshake failure happens
	 */
	OCF_AUTHENTICATION_FAILURE,
	OCF_NOT_ALLOWED_OXM,

	/** Insert all new error codes here!.*/
#ifdef WITH_PRESENCE
	OCF_PRESENCE_STOPPED = 128,
	OCF_PRESENCE_TIMEOUT,
	OCF_PRESENCE_DO_NOT_HANDLE,
#endif

	/** Request is denied by the user*/
	OCF_USER_DENIED_REQ,
	OCF_NOT_ACCEPTABLE,
	OCF_METHOD_NOT_ALLOWED,
#if 0
	/** ERROR code from server */
	OCF_FORBIDDEN_REQ,
	/** 403*/
	OCF_INTERNAL_SERVER_ERROR,
	/** 500*/
	OCF_NOT_IMPLEMENTED,
	/** 501*/
	OCF_BAD_GATEWAY,
	/** 502*/
	OCF_SERVICE_UNAVAILABLE,
	/** 503*/
	OCF_GATEWAY_TIMEOUT,
	/** 504*/
	OCF_PROXY_NOT_SUPPORTED,
	/** 505*/
#endif
	/** ERROR in ocf_init.*/
	OCF_EVENT_INIT_FAIL = 200,
	OCF_MANAGER_PERIODIC_PROCESS_INIT_FAIL,
	OCF_MEM_POOL_INIT_FAIL,
	OCF_RES_INIT_FAIL,
	OCF_REQUEST_INIT_FAIL,
	OCF_RECEIVE_QUEUE_INIT_FAIL,
	OCF_COAP_INIT_FAIL,
	OCF_SECURITY_INIT_FAIL,

	/** ERROR in stack.*/
	OCF_ERROR = 255
				/** Error status code - END HERE.*/
} ocf_result_t;

typedef enum {
	OCF_RESPONSE_OK = 0,
	OCF_RESPONSE_ERROR,
	OCF_RESPONSE_SEPARATE,
	OCF_RESPONSE_RESOURCE_CREATED = 201,
	OCF_RESPONSE_RESOURCE_DELETED = 202,
	OCF_RESPONSE_VALID = 203,
	OCF_RESPONSE_CHANGED = 204,
	OCF_RESPONSE_CONTENT = 205,
	OCF_RESPONSE_BAD_REQ = 400,
	OCF_RESPONSE_UNAUTHORIZED_REQ = 401,
	OCF_RESPONSE_BAD_OPT = 402,
	OCF_RESPONSE_FORBIDDEN = 403,
	OCF_RESPONSE_RESOURCE_NOT_FOUND = 404,
	OCF_RESPONSE_METHOD_NOT_ALLOWED = 405,
	OCF_RESPONSE_NOT_ACCEPTABLE = 406,
	OCF_RESPONSE_TOO_LARGE = 413,
	OCF_RESPONSE_UNSUPPORTED_MEDIA_TYPE = 415,
	OCF_RESPONSE_INTERNAL_SERVER_ERROR = 500,
	OCF_RESPONSE_NOT_IMPLEMENTED = 501,
	OCF_RESPONSE_BAD_GATEWAY = 502,
	OCF_RESPONSE_SERVICE_UNAVAILABLE = 503,
	OCF_RESPONSE_RETRANSMIT_TIMEOUT = 504,
	OCF_RESPONSE_PROXY_NOT_SUPPORTED = 505
} ocf_response_result_t;

typedef enum {
	OCF_DEFAULT_FLAGS = 0,
	OCF_SECURE = (1 << 0),
	OCF_IPV4 = (1 << 1),
	OCF_IPV6 = (1 << 2),
	OCF_UDP = (1 << 3),
	OCF_TCP = (1 << 4),
	OCF_MULTICAST = (1 << 7),
} ocf_transport_flags_t;

typedef enum {
	OCF_COAP = (1 << 0),
	OCF_COAPS = (1 << 1),
	OCF_HTTP = (1 << 2),
	OCF_HTTPS = (1 << 3),
	OCF_COAP_TCP = (1 << 4),
	OCF_COAPS_TCP = (1 << 5)
} ocf_protocol_t;

typedef enum {
	OCF_ADAPTER_IP = 0,		// IPv4 and IPv6
	OCF_ADAPTER_TCP			// CoAP over TCP
} ocf_adapter_t;

typedef struct {
	uint32_t addr[4];
	uint16_t port;
	ocf_transport_flags_t flags;
	unsigned char peerId[OCF_UUID_LENGTH];
} ocf_endpoint_s;

typedef enum {
	OIC_IF_INVALID = 0,
	OIC_IF_BASELINE = 1 << 0,
	OIC_IF_LL = 1 << 1,
	OIC_IF_B = 1 << 2,
	OIC_IF_R = 1 << 3,
	OIC_IF_RW = 1 << 4,
	OIC_IF_A = 1 << 5,
	OIC_IF_S = 1 << 6,
} ocf_interface_mask_t;

typedef enum {
	OCF_GET = 1,
	OCF_POST,
	OCF_PUT,
	OCF_DELETE
} ocf_method_t;

typedef enum {
	OCF_RES_100 = 1 << 0,
	OCF_SH_100 = 1 << 1,
} ocf_dmv_t;

typedef enum {
	OCF_1_0_0 = 2048,
	OIC_1_1_0 = 2112
} ocf_version_t;

typedef enum {
	OCF_CONFIRMABLE_MSG,
	OCF_NON_CONFIRMABLE_MSG,
	OCF_ACK_RESPONSE_MSG,
} ocf_message_type_t;

#define OCF_RES_100_VALUE "ocf.res.1.0.0"
#define OCF_SH_100_VALUE "ocf.res.1.0.0, ocf.sh.1.0.0"

#define OIC_IF_BASELINE_VALUE "oic.if.baseline"
#define OIC_IF_LL_VALUE "oic.if.ll"
#define OIC_IF_B_VALUE "oic.if.b"
#define OIC_IF_R_VALUE "oic.if.r"
#define OIC_IF_RW_VALUE "oic.if.rw"
#define OIC_IF_A_VALUE "oic.if.a"
#define OIC_IF_S_VALUE "oic.if.s"

#define OIC_IF_NAME "if"
#define OIC_RT_NAME "rt"

#define COAP_PREFIX "coap"
#define COAPS_PREFIX "coaps"
#define COAP_TCP_PREFIX "coap+tcp"
#define COAPS_TCP_PREFIX "coaps+tcp"

typedef struct {
	FILE *(*open)(const char *path, const char *mode);
	size_t(*read)(void *ptr, size_t size, size_t nmemb, FILE *stream);
	size_t(*write)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
	int (*close)(FILE *fp);
} ocf_persistent_storage_handler_s;

#define CORE_RES "/oic/res"
#define CORE_D "/oic/d"
#define CORE_P "/oic/p"
#define CORE_INTROSPECTION "/introspection"

#define TOKEN_LEN (8)

/*
 * ttl value for list items time to live.
 */
#define TTL_INTERVAL (300)	/* 5 minutes */

typedef struct {
	uint8_t token[TOKEN_LEN];
	uint8_t len;
} rt_token_s;

typedef struct {
	char *name;
	char *value;
} ocf_query_s;

typedef struct {
	ocf_query_s *query;
	int query_num;
} ocf_query_list_s;

typedef struct {
	ocf_query_list_s query_list;
	char *rt_query;
	char *if_query;
} ocf_request_query_set_s;

#ifdef __cplusplus
}
#endif							// __cplusplus
#endif							/* OCFTYPES_H_ */
