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

#include "unity.h"
#include "unity_fixture.h"

#include "ocf_types.h"
#include "ocf_resources.h"
#include "rt_ssl.h"
#include "rt_logger.h"

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"
#include "test_common.h"

static const char *TAG = "TC_MOCK_CLIENT";
static uint8_t *g_recv_buf = NULL;
static const char *g_send_buf = "ABCDE";
static uint16_t g_len_send_buf = 5;

TEST_GROUP(test_ssl_server);

static ocf_endpoint_s g_endpoint;

static int g_dtls_port_v4 = 0;

typedef enum {
	DTLS_HANDSHAKE_SUCCESS = 0,
	DTLS_HANDSHAKE_FAIL
} tc_t;

static void dtls_client_init(void);
static int dtls_client_handshake(tc_t tc);
static void dtls_client_request(void);
static void dtls_client_close(void);
static void dtls_client_terminate(void);

static pthread_cond_t g_rt_ssl_decrypt_condition;
static pthread_mutex_t g_mutex;

static ocf_persistent_storage_handler_s temp_doxm_handler = { test_doxm_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_cred_handler = { test_cred_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_acl2_handler = { test_acl2_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_pstat_handler = { test_pstat_fopen, fread, fwrite, fclose };

TEST_SETUP(test_ssl_server)
{
	create_security_data_files();
	ocf_sec_register_ps_handler(&temp_doxm_handler, &temp_pstat_handler, &temp_cred_handler, &temp_acl2_handler);
	ocf_init(OCF_CLIENT_SERVER, "Samsung", "1.0");
	rt_udp_get_secure_port_v4(&g_dtls_port_v4);
	pthread_mutex_init(&g_mutex, NULL);
	pthread_cond_init(&g_rt_ssl_decrypt_condition, NULL);
}

TEST_TEAR_DOWN(test_ssl_server)
{
	pthread_cond_destroy(&g_rt_ssl_decrypt_condition);
	pthread_mutex_destroy(&g_mutex);
	ocf_terminate();
	remove_security_data_files();
}

TEST(test_ssl_server, dtls_handshake_server)
{
	// Given
	dtls_client_init();

	// When
	int result = 0;
	result = dtls_client_handshake(DTLS_HANDSHAKE_SUCCESS);

	// Then
	TEST_ASSERT_TRUE(result);
	dtls_client_terminate();
}

IGNORE_TEST(test_ssl_server, dtls_handshake_fail)
{
	// Given
	dtls_client_init();

	// When
	int result = 0;
	result = dtls_client_handshake(DTLS_HANDSHAKE_FAIL);
	TEST_ASSERT_FALSE(result);
	sleep(15);

	// Then
	result = dtls_client_handshake(DTLS_HANDSHAKE_SUCCESS);
	TEST_ASSERT_TRUE(result);
	dtls_client_terminate();
}

static void get_wait_timespec(struct timespec *ts)
{
	struct timeval tp;
	gettimeofday(&tp, NULL);
	ts->tv_sec = tp.tv_sec;
	ts->tv_nsec = tp.tv_usec * 1000;
	ts->tv_sec += WAIT_TIME_SECONDS;
}

static int wait_condition(pthread_cond_t *cond)
{
	pthread_mutex_lock(&g_mutex);
	struct timespec ts;
	get_wait_timespec(&ts);
	int ret = pthread_cond_timedwait(cond, &g_mutex, &ts);
	pthread_mutex_unlock(&g_mutex);
	return ret;
}

static void test_recv_callback(uint8_t *packet, uint16_t len, const ocf_endpoint_s *endpoint)
{
	pthread_mutex_lock(&g_mutex);
	rt_mem_cpy(&g_endpoint, endpoint, sizeof(ocf_endpoint_s));

	g_recv_buf = packet;
	pthread_cond_signal(&g_rt_ssl_decrypt_condition);
	pthread_mutex_unlock(&g_mutex);
	return;
}

TEST(test_ssl_server, rt_ssl_decrypt)
{
	// Given
	g_recv_buf = NULL;
	rt_transport_set_receive_handler(test_recv_callback);
	dtls_client_init();
	dtls_client_handshake(DTLS_HANDSHAKE_SUCCESS);

	// When
	dtls_client_request();
	wait_condition(&g_rt_ssl_decrypt_condition);

	// Then
	TEST_ASSERT_EQUAL_STRING_LEN(g_send_buf, g_recv_buf, g_len_send_buf);
	dtls_client_terminate();
}

TEST(test_ssl_server, rt_ssl_close_connection)
{
	// Given
	rt_ssl_state_t ssl_state;
	g_recv_buf = NULL;
	rt_transport_set_receive_handler(test_recv_callback);
	dtls_client_init();
	dtls_client_handshake(DTLS_HANDSHAKE_SUCCESS);
	dtls_client_request();
	wait_condition(&g_rt_ssl_decrypt_condition);

	// when
	rt_ssl_check_session(&g_endpoint, &ssl_state);
	TEST_ASSERT_EQUAL_INT(RT_SSL_HANDSHAKE_OVER, ssl_state);
	dtls_client_close();
	sleep(2);

	// Then
	rt_ssl_check_session(&g_endpoint, &ssl_state);
	TEST_ASSERT_EQUAL_INT(RT_SSL_HANDSHAKE_NON, ssl_state);
	dtls_client_terminate();
}

TEST_GROUP_RUNNER(test_ssl_server)
{
	RUN_TEST_CASE(test_ssl_server, dtls_handshake_server);
	RUN_TEST_CASE(test_ssl_server, dtls_handshake_fail);
	RUN_TEST_CASE(test_ssl_server, rt_ssl_decrypt);
	RUN_TEST_CASE(test_ssl_server, rt_ssl_close_connection);
}

#ifndef CONFIG_IOTIVITY_RT

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_ssl_server);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif

mbedtls_net_context server_fd;
static const char *pers = "dtls_client";
static char *server_addr = "127.0.0.1";
static int g_test_ciphersuit_list[2] = {
	MBEDTLS_TLS_ECDH_ANON_WITH_AES_128_CBC_SHA256,
	0
};

mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_context ssl;
mbedtls_ssl_config conf;
mbedtls_timing_delay_context timer;

static void dtls_client_init(void)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	char server_port[6] = { 0, };
	mbedtls_net_init(&server_fd);
	mbedtls_ssl_init(&ssl);
	mbedtls_ssl_config_init(&conf);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
	sprintf(server_port, "%d", g_dtls_port_v4);
	mbedtls_net_connect(&server_fd, server_addr, server_port, MBEDTLS_NET_PROTO_UDP);
	mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT);
	mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_OPTIONAL);
	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_setup(&ssl, &conf);
	mbedtls_ssl_set_bio(&ssl, &server_fd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);
	mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
	mbedtls_ssl_conf_ciphersuites(&conf, g_test_ciphersuit_list);
	RT_LOG_D(TAG, "OUT : %s", __func__);
}

static int dtls_client_handshake(tc_t tc)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	int ret = 0;

	if (tc == DTLS_HANDSHAKE_SUCCESS) {
		do {
			ret = mbedtls_ssl_handshake(&ssl);
			// RT_LOG_E(TAG, " @@@@@@@@mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
		} while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);
	} else if (tc == DTLS_HANDSHAKE_FAIL) {
		while (ssl.state != MBEDTLS_SSL_HANDSHAKE_OVER) {
			ret = mbedtls_ssl_handshake_step(&ssl);
			if (ret != 0 || MBEDTLS_SSL_CLIENT_KEY_EXCHANGE == ssl.state) {
				mbedtls_ssl_session_reset(&ssl);
				return 0;
			}
		}
	}

	if (ret != 0) {
		RT_LOG_E(TAG, "failed! mbedtls_ssl_handshake returned -0x%x", -ret);
		return 0;
	}
	RT_LOG_D(TAG, "OUT : %s", __func__);
	return 1;
}

static void dtls_client_request(void)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	int ret;
	do {
		ret = mbedtls_ssl_write(&ssl, (unsigned char *)g_send_buf, g_len_send_buf);
	} while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	if (ret < 0) {
		RT_LOG_E(TAG, "failed! mbedtls_ssl_write returned %d", ret);
	}
	RT_LOG_D(TAG, " > WRITE TO SERVER  %d bytes written : %s", g_len_send_buf, g_send_buf);
	RT_LOG_D(TAG, "OUT : %s", __func__);
}

static void dtls_client_close(void)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	int ret;
	do {
		ret = mbedtls_ssl_close_notify(&ssl);
	} while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
	RT_LOG_D(TAG, "close_notify result: %d", ret);

	RT_LOG_D(TAG, "OUT : %s", __func__);
}

static void dtls_client_terminate(void)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	mbedtls_net_free(&server_fd);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	RT_LOG_D(TAG, "OUT : %s", __func__);
}
