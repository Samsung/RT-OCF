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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ocf_types.h"
#include "rt_transport.h"
#include "rt_list.h"
#include "rt_mem.h"
#include "rt_ssl.h"
#include "rt_endpoint.h"
#include "rt_logger.h"
#include "rt_utils.h"
#include "rt_uuid.h"
#include "rt_event.h"
#include "rt_sec_doxm_resource.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/pkcs12.h"
#include "mbedtls/ssl_internal.h"
#include "mbedtls/timing.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/ecp.h"

// Buffer to save a decrypted received packet
#define RT_SSL_MSG_BUF_LEN (2056)

#define PSK_LEN (256 / 8)
#define ONE_SET (1)
#define SEED_SIZE (16)

#define HANDSHAKE_TIMEOUT (10)

static const char *TAG = "RT_SSL";
#ifdef CONFIG_RT_OCF_MBEDTLS_DEBUG
static const char *MBED_TLS_TAG = "RT_MBEDTLS";
#define MBED_TLS_DEBUG_LEVEL (4)
#endif

/**
 * Data structure for holding the send and recv callbacks.
 */
typedef struct {
	ssl_recv_callback recv_callback;		   /**< Callback used to send data to upper layer. */
	ssl_send_callback send_callback;		   /**< Callback used to send data to socket layer. */
	ssl_handshake_callback handshake_callback; /**< Callback used to inform handshake failure to coap_transaction layer. */
} rt_sslcallback_s;

/**
 * Data structure for holding the data to be received.
 */
typedef struct {
	uint8_t *buff;
	size_t len;
	size_t loaded;
} rt_ssl_recv_buf_s;

typedef struct {
	mbedtls_ssl_context ssl;
	ocf_endpoint_s endpoint;
	rt_ssl_recv_buf_s recv_buf;
	//TODO : Enable below parm when implement onboarding
	//    uint8_t master[MASTER_SECRET_LEN];
	//    uint8_t random[2*RANDOM_LEN];
	mbedtls_timing_delay_context timer;
	rt_ssl_state_t handshake_state;
	rt_timer_s handshake_timer;
	rt_node_s node;
} rt_ssl_endpoint_s;

/**
 * Data structure for holding the mbedTLS interface related info.
 */
typedef struct {
	rt_list_s peer_list;

	mbedtls_entropy_context entropy;
	mbedtls_ctr_drbg_context rnd;
	//    mbedtls_x509_crt ca;
	//    mbedtls_x509_crt crt;
	//    mbedtls_pk_context pkey;

	mbedtls_ssl_config clientTlsConf;
	mbedtls_ssl_config serverTlsConf;
	mbedtls_ssl_config clientDtlsConf;
	mbedtls_ssl_config serverDtlsConf;

	rt_sslcallback_s trans_callbacks;
	// bool cipherFlag[2];
	// int selectedCipher;

	mbedtls_ssl_cookie_ctx cookieCtx;
	//  int timerId;
} rt_ssl_ctx_s;

typedef enum {
	SSL_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
	SSL_ECDH_ANON_WITH_AES_128_CBC_SHA256,
	SSL_CIPHER_MAX
} rt_ssl_cipher_t;

static rt_ssl_ctx_s *g_rt_ssl_ctx_s = NULL;
static uint8_t *g_rt_decryptBuffer = NULL;
static rt_ssl_get_psk_handler g_ssl_get_psk_cb = NULL;

static int g_rt_cipherSuitesList[SSL_CIPHER_MAX + 1] = {
	MBEDTLS_TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
	MBEDTLS_TLS_ECDH_ANON_WITH_AES_128_CBC_SHA256,
	0
};

typedef enum {
	RT_SSL_CURVE_SECP256R1,
	RT_SSL_CURVE_MAX
} rt_curve_info_t;

mbedtls_ecp_group_id rt_ssl_curve[RT_SSL_CURVE_MAX][2] = {
	{MBEDTLS_ECP_DP_SECP256R1, MBEDTLS_ECP_DP_NONE}
};

#ifdef CONFIG_RT_OCF_MBEDTLS_DEBUG
static void rt_ssl_mbedtls_dbg(void *ctx, int level, const char *file, int line, const char *str)
{
	printf("%s IN\n", __func__);
	((void)level);
	((void)file);
	((void)line);
	((void)ctx);

	printf("[%s] %s", MBED_TLS_TAG, str);
	printf("%s  OUT\n", __func__);
}
#endif

static rt_ssl_endpoint_s *rt_ssl_get_peer(const ocf_endpoint_s *endpoint)
{

	RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL_RET(endpoint, TAG, "endpoint", NULL);

	rt_node_s *itr = g_rt_ssl_ctx_s->peer_list.head;
	while (NULL != itr) {
		RT_LOG_D(TAG, "itr=%x", itr);
		rt_ssl_endpoint_s *var = (rt_ssl_endpoint_s *) rt_list_get_item(&(g_rt_ssl_ctx_s->peer_list), itr);
		itr = itr->next;
		if (rt_endpoint_is_equal(endpoint, (const ocf_endpoint_s *)(&(var->endpoint)))) {
			RT_LOG_D(TAG, "The matched peer is found");
			RT_LOG_D(TAG, "%s OUT", __func__);
			return var;
		}
	}

	RT_LOG_D(TAG, "The matched peer is not found");
	RT_LOG_D(TAG, "%s OUT", __func__);
	return NULL;
}

static int mbedtls_bio_sendCB(void *peer, const unsigned char *data, size_t dataLen)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL_RET(peer, TAG, "peer", -1);
	RT_VERIFY_NON_NULL_RET(data, TAG, "data", -1);

	g_rt_ssl_ctx_s->trans_callbacks.send_callback(data, dataLen, &((rt_ssl_endpoint_s *) peer)->endpoint);
	RT_LOG_D(TAG, "%s OUT", __func__);
	return (int)dataLen;
}

static int mbedtls_bio_recvCB(void *peer, unsigned char *data, size_t dataLen)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL_RET(peer, TAG, "peer", -1);
	RT_VERIFY_NON_NULL_RET(data, TAG, "data", -1);

	rt_ssl_recv_buf_s *recv_buf = &((rt_ssl_endpoint_s *) peer)->recv_buf;
	size_t retLen = (recv_buf->len > recv_buf->loaded ? recv_buf->len - recv_buf->loaded : 0);
	retLen = (retLen < dataLen ? retLen : dataLen);

	rt_mem_cpy(data, recv_buf->buff + recv_buf->loaded, retLen);
	recv_buf->loaded += retLen;

	RT_LOG_D(TAG, "%s OUT", __func__);
	return (int)retLen;
}

static int mbedtls_psk_CB(void *notUsed, mbedtls_ssl_context *ssl, const unsigned char *uuid, size_t uuid_len)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL_RET(g_ssl_get_psk_cb, TAG, "g_ssl_get_psk_cb is NULL", -1);
	RT_VERIFY_NON_NULL_RET(ssl, TAG, "ssl is NULL", -1);
	RT_VERIFY_NON_NULL_RET(uuid, TAG, "uuid is NULL", -1);

	if (uuid_len != RT_UUID_LEN) {
		RT_LOG_E(TAG, "UUID is invaild length, %s OUT", __func__);
		return -1;
	}
	(void)notUsed;
	uint8_t psk[PSK_LEN] = { 0 };
	size_t psk_len = 0;

	// Retrieve the credentials blob from security module
	if (OCF_OK == g_ssl_get_psk_cb(uuid, uuid_len, psk, &psk_len)) {
		rt_mem_cpy(((rt_ssl_endpoint_s *) ssl)->endpoint.peerId, uuid, uuid_len);
		RT_LOG_D(TAG, "PSK :");
		RT_LOG_BUFFER_D(TAG, psk, psk_len);
		RT_LOG_D(TAG, "%s OUT", __func__);
		return (mbedtls_ssl_set_hs_psk(ssl, psk, psk_len));
	}
	RT_LOG_D(TAG, "%s OUT", __func__);
	return -1;
}

void rt_ssl_set_callback(ssl_recv_callback recv_callback, ssl_send_callback send_callback)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL_VOID(g_rt_ssl_ctx_s, TAG, "g_rt_ssl_ctx_s");
	RT_VERIFY_NON_NULL_VOID(recv_callback, TAG, "recv_callback");
	RT_VERIFY_NON_NULL_VOID(send_callback, TAG, "send_callback");

	g_rt_ssl_ctx_s->trans_callbacks.recv_callback = recv_callback;
	g_rt_ssl_ctx_s->trans_callbacks.send_callback = send_callback;

	RT_LOG_D(TAG, "%s OUT", __func__);
}

static int rt_ssl_init_config(mbedtls_ssl_config *conf, uint8_t transport, uint8_t mode)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL_RET(conf, TAG, "conf", 0);

	mbedtls_ssl_config_init(conf);
	if (mbedtls_ssl_config_defaults(conf, mode, transport, MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
		RT_LOG_E(TAG, "Config initialization failed!");
		return -1;
	}
	mbedtls_ssl_conf_psk_cb(conf, mbedtls_psk_CB, NULL);
	mbedtls_ssl_conf_rng(conf, mbedtls_ctr_drbg_random, &g_rt_ssl_ctx_s->rnd);
	mbedtls_ssl_conf_curves(conf, rt_ssl_curve[RT_SSL_CURVE_SECP256R1]);
	mbedtls_ssl_conf_min_version(conf, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);
	mbedtls_ssl_conf_renegotiation(conf, MBEDTLS_SSL_RENEGOTIATION_DISABLED);
	mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED);

	if (MBEDTLS_SSL_TRANSPORT_DATAGRAM == transport && MBEDTLS_SSL_IS_SERVER == mode) {
		mbedtls_ssl_conf_dtls_cookies(conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &g_rt_ssl_ctx_s->cookieCtx);
	}
#ifdef CONFIG_RT_OCF_MBEDTLS_DEBUG
	mbedtls_ssl_conf_dbg(conf, rt_ssl_mbedtls_dbg, NULL);
	mbedtls_debug_set_threshold(MBED_TLS_DEBUG_LEVEL);
#endif

	RT_LOG_D(TAG, "%s OUT", __func__);
	return 0;
}

static void rt_setupcipher(mbedtls_ssl_config *config)
{
	//TODO: Need to set ciphersuite at OCF security implement
	RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL_VOID(config, TAG, "config");

	rt_uuid_t deviceuuid;
	rt_sec_doxm_get_deviceuuid_byte(deviceuuid);
	mbedtls_ssl_conf_ciphersuites(config, g_rt_cipherSuitesList);

	if (0 != mbedtls_ssl_conf_psk(config, deviceuuid, ONE_SET, deviceuuid, RT_UUID_LEN)) {
		RT_LOG_W(TAG, "psk_identity initialization failed!");
	}

	RT_LOG_D(TAG, "%s OUT", __func__);
}

static void rt_delete_ssl_endpoint(void *item)
{
	RT_LOG_D(TAG, "IN %s", __func__);
	rt_ssl_endpoint_s *peer = (rt_ssl_endpoint_s *) item;
	RT_VERIFY_NON_NULL_VOID(peer, TAG, "peer");
	mbedtls_ssl_free(&peer->ssl);
	RT_LOG_D(TAG, "OUT %s", __func__);
}

static void ssl_remove_peer_from_list(rt_ssl_endpoint_s *peer)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL_VOID(peer, TAG, "peer");

	rt_ssl_endpoint_s *var = rt_ssl_get_peer(&(peer->endpoint));
	if (!var) {
		RT_LOG_D(TAG, "The matched peer is not found", __func__);
		return;
	}
	rt_list_delete_by_node(&(g_rt_ssl_ctx_s->peer_list), &var->node);
	rt_delete_ssl_endpoint(var);
	rt_mem_free(var);

	RT_LOG_I(TAG, "Current peer_list count : %d ", g_rt_ssl_ctx_s->peer_list.count);
	RT_LOG_D(TAG, "%s OUT", __func__);
}

static rt_ssl_endpoint_s *rt_new_ssl_endpoint(const ocf_endpoint_s *endpoint, mbedtls_ssl_config *config)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL_RET(endpoint, TAG, "endpoint", NULL);
	RT_VERIFY_NON_NULL_RET(config, TAG, "config", NULL);

	rt_ssl_endpoint_s *peer = (rt_ssl_endpoint_s *) rt_mem_alloc(sizeof(rt_ssl_endpoint_s));
	RT_VERIFY_NON_NULL_RET(peer, TAG, "peer malloc failed!", NULL);

	rt_mem_cpy(&peer->endpoint, (ocf_endpoint_s *) endpoint, sizeof(ocf_endpoint_s));

	if (0 != mbedtls_ssl_setup(&peer->ssl, config)) {
		RT_LOG_E(TAG, "Setup failed");
		rt_mem_free(peer);
		peer = NULL;
		RT_LOG_D(TAG, "%s OUT", __func__);
		return NULL;
	}

	mbedtls_ssl_set_bio(&peer->ssl, peer, mbedtls_bio_sendCB, mbedtls_bio_recvCB, NULL);
	if (MBEDTLS_SSL_TRANSPORT_DATAGRAM == config->transport) {
		mbedtls_ssl_set_timer_cb(&peer->ssl, &peer->timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
		if (MBEDTLS_SSL_IS_SERVER == config->endpoint) {
			char buf[40];
			rt_endpoint_get_addr_str(endpoint, buf, sizeof(buf));
			if (0 != mbedtls_ssl_set_client_transport_id(&peer->ssl, (const unsigned char *)buf, strlen(buf) + 1)) {
				RT_LOG_E(TAG, "Transport id setup failed!");
				mbedtls_ssl_free(&peer->ssl);
				rt_mem_free(peer);
				peer = NULL;
				RT_LOG_D(TAG, "Out %s", __func__);
				return NULL;
			}
		}
	}

	RT_LOG_D(TAG, "%s OUT", __func__);
	return peer;
}

static ocf_result_t rt_make_new_peer_node(const ocf_endpoint_s *endpoint, mbedtls_ssl_config *config, rt_ssl_endpoint_s **peer)
{
	*peer = rt_new_ssl_endpoint(endpoint, config);
	RT_VERIFY_NON_NULL_RET(*peer, TAG, "new peer failed", OCF_COMM_ERROR);

	rt_setupcipher(config);
	rt_list_insert(&(g_rt_ssl_ctx_s->peer_list), &((*peer)->node));

	RT_LOG_D(TAG, "Current peer_list count : %d ", g_rt_ssl_ctx_s->peer_list.count);

	rt_timer_set(&((*peer)->handshake_timer), HANDSHAKE_TIMEOUT * RT_CLOCK_SECOND);
	rt_event_set_signal();

	return OCF_OK; 
}

static ocf_result_t rt_ssl_error_check(rt_ssl_endpoint_s *peer, int ret, unsigned char msg, const char *str)
{
	if (0 != (ret) && MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY != (int)(ret) &&
		MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED != (int)(ret) && MBEDTLS_ERR_SSL_WANT_READ != (int)(ret) && MBEDTLS_ERR_SSL_WANT_WRITE != (int)(ret) && MBEDTLS_ERR_SSL_NON_FATAL != (int)(ret) && MBEDTLS_SSL_ALERT_MSG_USER_CANCELED != (int)(ret) && MBEDTLS_SSL_ALERT_MSG_NO_RENEGOTIATION != (int)(ret) && MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_EXT != (int)(ret) && MBEDTLS_SSL_ALERT_MSG_CLOSE_NOTIFY != (int)(ret) && MBEDTLS_SSL_ALERT_MSG_NO_CERT != (int)(ret) && MBEDTLS_SSL_ALERT_MSG_BAD_CERT != (int)(ret) && MBEDTLS_SSL_ALERT_MSG_UNSUPPORTED_CERT != (int)(ret) && MBEDTLS_SSL_ALERT_MSG_CERT_REVOKED != (int)(ret) && MBEDTLS_SSL_ALERT_MSG_CERT_EXPIRED != (int)(ret) && MBEDTLS_SSL_ALERT_MSG_CERT_UNKNOWN != (int)(ret) && MBEDTLS_SSL_ALERT_MSG_INAPROPRIATE_FALLBACK != (int)(ret) && MBEDTLS_SSL_ALERT_MSG_UNRECOGNIZED_NAME != (int)(ret) && MBEDTLS_SSL_ALERT_MSG_UNKNOWN_PSK_IDENTITY != (int)(ret) && MBEDTLS_SSL_ALERT_MSG_NO_APPLICATION_PROTOCOL != (int)(ret)) {

		RT_LOG_E(TAG, "%s: -0x%x", str, -(ret));
		if ((int)MBEDTLS_ERR_SSL_FATAL_ALERT_MESSAGE != (int)(ret) && (int)MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO != (int)(ret)) {
			mbedtls_ssl_send_alert_message(&(peer)->ssl, MBEDTLS_SSL_ALERT_LEVEL_FATAL, (msg));
		}
		if (peer->handshake_state == RT_SSL_HANDSHAKE_ONGOING) {
			peer->handshake_state = RT_SSL_HANDSHAKE_FAILURE;
			g_rt_ssl_ctx_s->trans_callbacks.handshake_callback(&peer->endpoint);
		}
		ssl_remove_peer_from_list(peer);

		if ((int)MBEDTLS_ERR_SSL_BAD_HS_CLIENT_HELLO != (int)(ret)) {
			//TOD0: error handler to upper layer by callback??
		}
		return OCF_ERROR;
	}
	return OCF_OK;
}

bool rt_ssl_get_nearest_wakeup_time_of_peers(rt_clock_time_t *wakeup_time)
{
	RT_VERIFY_NON_NULL_RET(wakeup_time, TAG, NULL, false);
	RT_VERIFY_NON_NULL_RET(g_rt_ssl_ctx_s, TAG, NULL, false);
	RT_VERIFY_NON_ZERO_RET(g_rt_ssl_ctx_s->peer_list.count, TAG, NULL, false);

	bool ret = false;
	rt_clock_time_t internal_wakeup_time;

	rt_node_s *itr = g_rt_ssl_ctx_s->peer_list.head;

	while (itr) {
		rt_ssl_endpoint_s *var = (rt_ssl_endpoint_s *) rt_list_get_item(&g_rt_ssl_ctx_s->peer_list, itr);

		RT_VERIFY_NON_NULL_RET(var, TAG, NULL, ret);

		if (var->handshake_timer.interval) {

			internal_wakeup_time = var->handshake_timer.start + var->handshake_timer.interval;
			if ((internal_wakeup_time < *wakeup_time) || !ret) {
				*wakeup_time = internal_wakeup_time;
				ret = true;
			}
		}
		itr = itr->next;
	}

	return ret;
}

void rt_ssl_set_handshake_callback(ssl_handshake_callback handshake_callback)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL_VOID(g_rt_ssl_ctx_s, TAG, "g_rt_ssl_ctx_s");

	g_rt_ssl_ctx_s->trans_callbacks.handshake_callback = handshake_callback;

	RT_LOG_D(TAG, "%s OUT", __func__);
}

void rt_ssl_check_handshake_timeout(void)
{
	RT_VERIFY_NON_NULL_VOID(g_rt_ssl_ctx_s, TAG, "g_rt_ssl_ctx_s");
	rt_node_s *itr = g_rt_ssl_ctx_s->peer_list.head;

	while (itr) {
		rt_ssl_endpoint_s *var = (rt_ssl_endpoint_s *) rt_list_get_item(&g_rt_ssl_ctx_s->peer_list, itr);
		itr = itr->next;
		if (var->handshake_timer.interval != 0 && rt_timer_expired(&var->handshake_timer) && var->handshake_state == RT_SSL_HANDSHAKE_ONGOING) {
			rt_endpoint_log(OCF_LOG_ERROR, TAG, &var->endpoint);
			RT_LOG_E(TAG, "=> handshake timer is expired");
			g_rt_ssl_ctx_s->trans_callbacks.handshake_callback(&var->endpoint);
			ssl_remove_peer_from_list(var);
		}
	}
}

void rt_ssl_register_psk_handler(rt_ssl_get_psk_handler get_psk_handler)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	g_ssl_get_psk_cb = get_psk_handler;
	RT_LOG_D(TAG, "%s OUT", __func__);
}

ocf_result_t rt_ssl_init(void)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	g_rt_ssl_ctx_s = (rt_ssl_ctx_s *) rt_mem_alloc(sizeof(rt_ssl_ctx_s));
	RT_VERIFY_NON_NULL_RET(g_rt_ssl_ctx_s, TAG, "g_rt_ssl_ctx_s malloc failed!", OCF_MEM_FULL);

	rt_list_init(&(g_rt_ssl_ctx_s->peer_list), sizeof(rt_ssl_endpoint_s), RT_MEMBER_OFFSET(rt_ssl_endpoint_s, node));

	// mbedtls_x509_crt_init(&cacert);
	mbedtls_entropy_init(&g_rt_ssl_ctx_s->entropy);
	mbedtls_ctr_drbg_init(&g_rt_ssl_ctx_s->rnd);
	unsigned char seed[SEED_SIZE];
	rt_random_rand_to_buffer((uint8_t *) seed, SEED_SIZE);

	if (0 != mbedtls_ctr_drbg_seed(&g_rt_ssl_ctx_s->rnd, mbedtls_entropy_func, &g_rt_ssl_ctx_s->entropy, seed, sizeof(seed))) {
		RT_LOG_E(TAG, "Seed initialization failed!");
		rt_ssl_terminate();
		return OCF_ERROR;
	}
	mbedtls_ctr_drbg_set_prediction_resistance(&g_rt_ssl_ctx_s->rnd, MBEDTLS_CTR_DRBG_PR_OFF);

	mbedtls_ssl_cookie_init(&g_rt_ssl_ctx_s->cookieCtx);
	if (0 != mbedtls_ssl_cookie_setup(&g_rt_ssl_ctx_s->cookieCtx, mbedtls_ctr_drbg_random, &g_rt_ssl_ctx_s->rnd)) {
		RT_LOG_E(TAG, "Cookie setup failed!");
		rt_ssl_terminate();
		return OCF_ERROR;
	}

	if (0 != rt_ssl_init_config(&g_rt_ssl_ctx_s->clientDtlsConf, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_IS_CLIENT)) {
		RT_LOG_E(TAG, "Client DTLS config initialization failed!");
		rt_ssl_terminate();
		return OCF_ERROR;
	}

	if (0 != rt_ssl_init_config(&g_rt_ssl_ctx_s->serverDtlsConf, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_IS_SERVER)) {
		RT_LOG_E(TAG, "Server DTLS config initialization failed!");
		rt_ssl_terminate();
		return OCF_ERROR;
	}

	if (0 != rt_ssl_init_config(&g_rt_ssl_ctx_s->clientTlsConf, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_IS_CLIENT)) {
		RT_LOG_E(TAG, "Client TLS config initialization failed!");
		rt_ssl_terminate();
		return OCF_ERROR;
	}
	if (0 != rt_ssl_init_config(&g_rt_ssl_ctx_s->serverTlsConf, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_IS_SERVER)) {
		RT_LOG_E(TAG, "Server TLS config initialization failed!");
		rt_ssl_terminate();
		return OCF_ERROR;
	}
	// create decrypt buffer
	g_rt_decryptBuffer = (uint8_t *) rt_mem_alloc(RT_SSL_MSG_BUF_LEN);
	if (NULL == g_rt_decryptBuffer) {
		RT_LOG_E(TAG, "Decrypt buffer malloc failed");
		rt_ssl_terminate();
		return OCF_MEM_FULL;
	}

	RT_LOG_D(TAG, "%s OUT", __func__);

	return OCF_OK;
}

ocf_result_t rt_ssl_check_session(ocf_endpoint_s *endpoint, rt_ssl_state_t *ssl_state)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL(endpoint, TAG, "endpoint");
	RT_VERIFY_NON_NULL(ssl_state, TAG, "ssl_state");

	rt_ssl_endpoint_s *peer = rt_ssl_get_peer(endpoint);
	if (!peer) {
		*ssl_state = RT_SSL_HANDSHAKE_NON;
		RT_LOG_D(TAG, "Current ssl_state = RT_SSL_HANDSHAKE_NON");
	} else {
		if (MBEDTLS_SSL_HANDSHAKE_OVER == peer->ssl.state) {
			*ssl_state = RT_SSL_HANDSHAKE_OVER;
			RT_LOG_D(TAG, "Current ssl_state = MBEDTLS_SSL_HANDSHAKE_OVER");
		} else {
			*ssl_state = RT_SSL_HANDSHAKE_ONGOING;
			RT_LOG_D(TAG, "Current ssl_state = RT_SSL_HANDSHAKE_ONGOING");
		}
	}
	RT_LOG_D(TAG, "%s OUT", __func__);
	return OCF_OK;
}

ocf_result_t rt_ssl_initialize_handshake(const ocf_endpoint_s *endpoint)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL(endpoint, TAG, "endpoint");

	int ret;
	mbedtls_ssl_config *config = NULL;

	rt_ssl_endpoint_s *peer = rt_ssl_get_peer(endpoint);

	if (NULL != peer) {
		RT_LOG_D(TAG, "The handshake is re-started");
		ssl_remove_peer_from_list(peer);
	}

	if (OCF_UDP & endpoint->flags) {
		config = &g_rt_ssl_ctx_s->clientDtlsConf;
	} else if (OCF_TCP & endpoint->flags) {
		config = &g_rt_ssl_ctx_s->clientTlsConf;
	} else {
		RT_LOG_D(TAG, "%s OUT", __func__);
		return OCF_COMM_ERROR;
	}

	ocf_result_t result = rt_make_new_peer_node(endpoint, config, &peer);
	if (OCF_OK != result) {
		RT_LOG_E(TAG, "Failed to make new peer");
		return result;
	}

	//Initialize Handshake
	peer->handshake_state = RT_SSL_HANDSHAKE_ONGOING;
	while (MBEDTLS_SSL_HANDSHAKE_OVER != peer->ssl.state) {
		ret = mbedtls_ssl_handshake(&peer->ssl);
		if (MBEDTLS_ERR_SSL_CONN_EOF == ret) {
			break;
		}
	}

	RT_LOG_D(TAG, "%s OUT", __func__);

	return OCF_OK;
}

ocf_result_t rt_ssl_encrypt(const uint8_t *packet, uint16_t len, const ocf_endpoint_s *endpoint)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL(packet, TAG, "packet");
	RT_VERIFY_NON_NULL(len, TAG, "len");
	RT_VERIFY_NON_NULL(endpoint, TAG, "endpoint");

	rt_ssl_endpoint_s *peer = rt_ssl_get_peer(endpoint);

	int ret;
	if (NULL == peer || (MBEDTLS_SSL_HANDSHAKE_OVER != peer->ssl.state)) {
		RT_LOG_E(TAG, "The session is not established, do rt_ssl_initialize_handshake first");
		return OCF_ERROR;
	}
	//TODO: Need to error handler
	if (MBEDTLS_SSL_HANDSHAKE_OVER == peer->ssl.state) {

		unsigned char *dataBuf = (unsigned char *)(packet);
		size_t written = 0;
		do {
			ret = mbedtls_ssl_write(&peer->ssl, dataBuf, len - written);
			if (ret < 0) {
				if (MBEDTLS_ERR_SSL_WANT_WRITE != ret) {
					RT_LOG_E(TAG, "mbedTLS write failed! returned 0x%x", -ret);
					ssl_remove_peer_from_list(peer);
					return OCF_COMM_ERROR;
				}
				continue;
			}
			RT_LOG_D(TAG, "mbedTLS write returned with sent bytes[%d]", ret);

			dataBuf += ret;
			written += ret;
		} while (len > written);
	}

	RT_LOG_D(TAG, "%s OUT", __func__);

	return OCF_OK;
}

ocf_result_t rt_ssl_decrypt(uint8_t *packet, uint16_t len, ocf_endpoint_s *endpoint)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL(packet, TAG, "packet");
	RT_VERIFY_NON_NULL(len, TAG, "len");
	RT_VERIFY_NON_NULL(endpoint, TAG, "endpoint");

	rt_ssl_endpoint_s *peer = rt_ssl_get_peer(endpoint);

	if (NULL == peer) {
		mbedtls_ssl_config *config = NULL;
		if (OCF_UDP & endpoint->flags) {
			config = &g_rt_ssl_ctx_s->serverDtlsConf;
		} else if (OCF_TCP & endpoint->flags) {
			config = &g_rt_ssl_ctx_s->serverTlsConf;
		} else {
			RT_LOG_D(TAG, "%s OUT", __func__);
			return OCF_COMM_ERROR;
		}

		ocf_result_t result = rt_make_new_peer_node(endpoint, config, &peer);
		if (OCF_OK != result) {
			RT_LOG_E(TAG, "Failed to make new peer");
			return result;
		}
	}

	peer->recv_buf.buff = packet;
	peer->recv_buf.len = len;
	peer->recv_buf.loaded = 0;

	int ret;
	while (MBEDTLS_SSL_HANDSHAKE_OVER != peer->ssl.state) {
		if (RT_SSL_HANDSHAKE_NON == peer->handshake_state) {
			peer->handshake_state = RT_SSL_HANDSHAKE_ONGOING;
		}
		ret = mbedtls_ssl_handshake_step(&peer->ssl);
		if (MBEDTLS_ERR_SSL_CONN_EOF == ret) {
			break;
		}
		if (MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED == ret) {
			RT_LOG_D(TAG, "Hello verification requested");
			mbedtls_ssl_session_reset(&peer->ssl);
			char buf[40];
			rt_endpoint_get_addr_str(&(peer->endpoint), buf, sizeof(buf));
			mbedtls_ssl_set_client_transport_id(&peer->ssl, (const unsigned char *)buf, strlen(buf) + 1);
			ret = mbedtls_ssl_handshake_step(&peer->ssl);
		}
		if (MBEDTLS_SSL_IS_CLIENT == peer->ssl.conf->endpoint) {
			uint32_t flags = mbedtls_ssl_get_verify_result(&peer->ssl);
			if (0 != flags) {
				RT_LOG_E(TAG, "ERROR in mbedtls_ssl_get_verify_result");
			}
		}
		ocf_result_t res = rt_ssl_error_check(peer, ret, MBEDTLS_SSL_ALERT_MSG_HANDSHAKE_FAILURE, "Handshake error");
		if (res != OCF_OK) {
			return res;
		}
	}

	if (MBEDTLS_SSL_HANDSHAKE_OVER == peer->ssl.state) {
		if (RT_SSL_HANDSHAKE_OVER != peer->handshake_state) {
			RT_LOG_D(TAG, "HANDSHAKE DONE!");
			peer->handshake_state = RT_SSL_HANDSHAKE_OVER;
			rt_timer_reset(&peer->handshake_timer);
			rt_event_set_signal();
			return OCF_OK;
		}

		rt_mem_cpy(endpoint->peerId, peer->endpoint.peerId, RT_UUID_LEN);

		bool read_more = false;
		do {
			if (NULL == g_rt_decryptBuffer) {
				RT_LOG_E(TAG, "decrypt buffer is NULL");
				return OCF_COMM_ERROR;
			}
			memset(g_rt_decryptBuffer, 0, RT_SSL_MSG_BUF_LEN);

			do {
				ret = mbedtls_ssl_read(&peer->ssl, g_rt_decryptBuffer, RT_SSL_MSG_BUF_LEN);
			} while (ret == MBEDTLS_ERR_SSL_WANT_READ);

			if (MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY == ret) {
				RT_LOG_D(TAG, "Connection was closed gracefully");
				ssl_remove_peer_from_list(peer);
				return OCF_OK;
			}

			if (0 > ret) {
				RT_LOG_E(TAG, "mbedtls_ssl_read returned -0x%x", -ret);
				ssl_remove_peer_from_list(peer);
				return OCF_COMM_ERROR;
			} else if (0 < ret) {
				if ((endpoint->flags & (OCF_SECURE)) && (endpoint->flags & (OCF_UDP))) {
					g_rt_ssl_ctx_s->trans_callbacks.recv_callback(g_rt_decryptBuffer, (uint8_t) ret, endpoint);
				}
				size_t remained = mbedtls_ssl_get_bytes_avail(&peer->ssl);
				if (0 < remained && MBEDTLS_SSL_TRANSPORT_STREAM == peer->ssl.conf->transport) {
					RT_LOG_D(TAG, "need to read %zu bytes more", remained);
					read_more = true;
				}
			} else {
				RT_LOG_D(TAG, "ret is ZERO");
			}
		} while (read_more);
	}
	RT_LOG_D(TAG, "%s OUT", __func__);
	return OCF_OK;
}

static void ssl_close_connection_all(void)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	rt_list_terminate(&(g_rt_ssl_ctx_s->peer_list), rt_delete_ssl_endpoint);

	RT_LOG_D(TAG, "%s OUT", __func__);
}

ocf_result_t rt_ssl_close_connection(ocf_endpoint_s *endpoint)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	if (NULL == endpoint) {
		RT_LOG_E(TAG, "Endpont is NULL");
		RT_LOG_D(TAG, "OUT %s", __func__);
		return OCF_INVALID_PARAM;
	}

	rt_ssl_endpoint_s *peer = NULL;

	peer = rt_ssl_get_peer(endpoint);

	if (NULL == peer) {
		RT_LOG_D(TAG, "Secure connetion does not exist");
		RT_LOG_D(TAG, "OUT %s", __func__);
		return OCF_ERROR;
	}

	int ret = 0;
	do {
		ret = mbedtls_ssl_close_notify(&peer->ssl);
	} while (MBEDTLS_ERR_SSL_WANT_WRITE == ret);

	ssl_remove_peer_from_list(peer);

	RT_LOG_D(TAG, "%s OUT", __func__);
	return OCF_OK;
}

ocf_result_t rt_ssl_terminate(void)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	if (NULL == g_rt_ssl_ctx_s) {
		RT_LOG_W(TAG, "SSL is not initialized");
		return OCF_ERROR;
	}
	mbedtls_ssl_config_free(&g_rt_ssl_ctx_s->clientTlsConf);
	mbedtls_ssl_config_free(&g_rt_ssl_ctx_s->serverTlsConf);
	mbedtls_ssl_config_free(&g_rt_ssl_ctx_s->clientDtlsConf);
	mbedtls_ssl_config_free(&g_rt_ssl_ctx_s->serverDtlsConf);
	mbedtls_ssl_cookie_free(&g_rt_ssl_ctx_s->cookieCtx);
	mbedtls_ctr_drbg_free(&g_rt_ssl_ctx_s->rnd);
	mbedtls_entropy_free(&g_rt_ssl_ctx_s->entropy);

	ssl_close_connection_all();
	rt_mem_free(g_rt_ssl_ctx_s);
	g_rt_ssl_ctx_s = NULL;
	rt_mem_free(g_rt_decryptBuffer);
	g_rt_decryptBuffer = NULL;
	g_ssl_get_psk_cb = NULL;

	RT_LOG_D(TAG, "%s OUT", __func__);

	return OCF_OK;
}
