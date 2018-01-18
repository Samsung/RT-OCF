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
#include "rt_endpoint.h"
#include "rt_thread.h"
#include "test_common.h"

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <arpa/inet.h>

#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/ssl.h"
#include "mbedtls/ssl_cookie.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/error.h"
#include "mbedtls/debug.h"
#include "mbedtls/timing.h"

#define DEBUG_LEVEL 0
#define BUFSIZE 1024

static const char *TAG = "TC_MOCK_SERVER";
static rt_thread_s tid;
static int g_server_on = 0;
static int g_test_port = 0;
static uint8_t *g_recv_buf = NULL;

TEST_GROUP(test_ssl_client);

static void start_mock_server(void);
static void stop_mock_server(void);
static ocf_endpoint_s g_endpoint;

pthread_cond_t g_rt_ssl_encrypt_condition;
pthread_cond_t g_close_notify_condition;
pthread_mutex_t g_mutex;
mbedtls_ssl_context ssl;
int g_is_handshaketest = 0;

static ocf_persistent_storage_handler_s temp_doxm_handler = { test_doxm_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_cred_handler = { test_cred_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_acl2_handler = { test_acl2_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_pstat_handler = { test_pstat_fopen, fread, fwrite, fclose };

TEST_SETUP(test_ssl_client)
{
	create_security_data_files();
	ocf_sec_register_ps_handler(&temp_doxm_handler, &temp_pstat_handler, &temp_cred_handler, &temp_acl2_handler);
	ocf_init(OCF_CLIENT_SERVER, "Samsung", "1.0");
	pthread_mutex_init(&g_mutex, NULL);
	pthread_cond_init(&g_rt_ssl_encrypt_condition, NULL);
	pthread_cond_init(&g_close_notify_condition, NULL);
}

TEST_TEAR_DOWN(test_ssl_client)
{
	pthread_cond_destroy(&g_rt_ssl_encrypt_condition);
	pthread_cond_destroy(&g_close_notify_condition);
	pthread_mutex_destroy(&g_mutex);
	ocf_terminate();
	remove_security_data_files();
	sleep(1);
}

static void get_wait_timespec(struct timespec *ts)
{
	struct timeval tp;
	gettimeofday(&tp, NULL);
	ts->tv_sec = tp.tv_sec;
	ts->tv_nsec = tp.tv_usec * 1000;
	ts->tv_sec += WAIT_TIME_SECONDS;
}

TEST(test_ssl_client, ssl_check_session)
{
	// given
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 5555, OCF_IPV4);

	rt_ssl_state_t ssl_state;

	// when
	rt_ssl_check_session(&endpoint, &ssl_state);

	// then
	TEST_ASSERT_EQUAL_INT(RT_SSL_HANDSHAKE_NON, ssl_state);
}

TEST(test_ssl_client, rt_ssl_encrypt_invalid_argument)
{
	//Given
	char *str = "ABCD";
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 8080, OCF_IPV4 | OCF_SECURE);

	// When
	ocf_result_t ret1 = rt_ssl_encrypt((uint8_t *) str, strlen(str), NULL);
	ocf_result_t ret2 = rt_ssl_encrypt(NULL, strlen(str), &endpoint);
	ocf_result_t ret3 = rt_ssl_encrypt((uint8_t *) str, 0, &endpoint);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, ret1);
	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, ret2);
	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, ret3);
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

static ocf_result_t init_handshake(void)
{
	ocf_endpoint_s temp_endpoint;
	rt_endpoint_set(&temp_endpoint, "127.0.0.1", g_test_port, OCF_IPV4 | OCF_SECURE | OCF_UDP);
	g_endpoint = temp_endpoint;

	ocf_result_t ret = rt_ssl_initialize_handshake((const ocf_endpoint_s *)&g_endpoint);

	int count = WAIT_TIME_SECONDS * 10;
	while (count--) {
		rt_ssl_state_t ssl_state;
		rt_ssl_check_session(&g_endpoint, &ssl_state);
		if (RT_SSL_HANDSHAKE_OVER == ssl_state) {
			break;
		}
		usleep(100 * 1000);
	}

	if (0 == count) {
		ret = OCF_TIMEOUT;
	}

	return ret;
}

TEST(test_ssl_client, rt_ssl_initialize_handshake)
{
	// Given
	ocf_result_t ret = OCF_ERROR;
	rt_ssl_state_t ssl_state;
	g_is_handshaketest = 1;

	// When
	ret = init_handshake();

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	rt_ssl_check_session(&g_endpoint, &ssl_state);
	TEST_ASSERT_EQUAL_INT(RT_SSL_HANDSHAKE_OVER, ssl_state);
}

static void rt_ssl_test_recv_callback(uint8_t *packet, uint16_t len, const ocf_endpoint_s *endpoint)
{
	pthread_mutex_lock(&g_mutex);
	pthread_cond_signal(&g_rt_ssl_encrypt_condition);
	g_recv_buf = packet;
	pthread_mutex_unlock(&g_mutex);
	return;
}

TEST(test_ssl_client, rt_ssl_encrypt)
{
	// Given
	ocf_result_t res = OCF_ERROR;
	char *packet = "ABCDE";
	uint16_t len = strlen(packet);
	g_recv_buf = NULL;
	g_is_handshaketest = 0;

	rt_transport_set_receive_handler(rt_ssl_test_recv_callback);

	init_handshake();

	//when
	res = rt_ssl_encrypt((uint8_t *) packet, len, (const ocf_endpoint_s *)&g_endpoint);
	wait_condition(&g_rt_ssl_encrypt_condition);

	//then
	TEST_ASSERT_EQUAL_INT(OCF_OK, res);
	TEST_ASSERT_EQUAL_STRING_LEN(packet, g_recv_buf, len);
}

TEST(test_ssl_client, rt_ssl_close_connection)
{
	// Given
	ocf_result_t res = OCF_ERROR;
	rt_ssl_state_t ssl_state;
	g_is_handshaketest = 0;

	init_handshake();

	// When
	res = rt_ssl_close_connection(&g_endpoint);

	// Then
	int ret = wait_condition(&g_close_notify_condition);
	TEST_ASSERT_EQUAL(0, ret);

	TEST_ASSERT_EQUAL_INT(OCF_OK, res);
	rt_ssl_check_session(&g_endpoint, &ssl_state);
	TEST_ASSERT_EQUAL_INT(RT_SSL_HANDSHAKE_NON, ssl_state);
}

TEST_GROUP_RUNNER(test_ssl_client)
{
	start_mock_server();
	RUN_TEST_CASE(test_ssl_client, rt_ssl_encrypt_invalid_argument);
	RUN_TEST_CASE(test_ssl_client, rt_ssl_initialize_handshake);
	RUN_TEST_CASE(test_ssl_client, rt_ssl_encrypt);
	RUN_TEST_CASE(test_ssl_client, rt_ssl_close_connection);
	while (!g_server_on) {
		sleep(1);
	}
	sleep(2);
	stop_mock_server();
}

#ifndef CONFIG_IOTIVITY_RT

static void RunAllTests(void)
{

	RUN_TEST_GROUP(test_ssl_client);

}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif

static void my_debug(void *ctx, int level, const char *file, int line, const char *str)
{
	((void)level);

	RT_LOG_D(TAG, "%s:%04d: %s", file, line, str);
}

int g_terminated = 0;

int len = 0;
size_t cliip_len;
unsigned char buf[1024];
static const char *pers = "mock_server";
unsigned char client_ip[16] = { 0 };

mbedtls_ssl_cookie_ctx cookie_ctx;
mbedtls_net_context listen_fd;
mbedtls_net_context client_fd;
mbedtls_entropy_context entropy;
mbedtls_ctr_drbg_context ctr_drbg;
mbedtls_ssl_config conf;
mbedtls_timing_delay_context timer;

#define RESULT_ERROR -1
#define RESULT_OK 0
#define RESULT_RESET 1
#define RESULT_CLOSE_NOTIFY 2

#define SELECT_TIME_SEC 1

#ifndef FD_SETSIZE
#define FD_SETSIZE	(CONFIG_NFILE_DESCRIPTORS + CONFIG_NSOCKET_DESCRIPTORS)
#endif

#ifdef CONFIG_IOTIVITY_RT
#define RCV_THREAD_STACK_SIZE   10240
#else
#define RCV_THREAD_STACK_SIZE   16384
#endif

static int g_test_ciphersuit_list[2] = {
	MBEDTLS_TLS_ECDH_ANON_WITH_AES_128_CBC_SHA256,
	0
};

static void *dtls_server_runner(void *args);
static void dtls_server_init(void);
static int dtls_server_bind(void);
static int dtls_server_generate_seeding_random_number(void);
static int dtls_server_set_dtls_data(void);
static void dtls_server_reset(void);
static int dtls_server_wait_client(void);
static int dtls_server_handshake(void);
static int dtls_server_read_request(void);
static int dtls_server_write_response(void);
static int dtls_server_close_notify(void);
static void dtls_server_terminate(void);

static void start_mock_server(void)
{
	RT_LOG_I(TAG, "IN : %s", __func__);

	g_terminated = 0;
	g_server_on = 0;

	mbedtls_net_init(&listen_fd);
	mbedtls_net_init(&client_fd);
	mbedtls_ssl_config_init(&conf);
	mbedtls_ssl_cookie_init(&cookie_ctx);
	mbedtls_entropy_init(&entropy);
	mbedtls_ctr_drbg_init(&ctr_drbg);
	mbedtls_debug_set_threshold(DEBUG_LEVEL);

	rt_thread_init(&tid, dtls_server_runner, NULL, 0, NULL);

	while (!g_server_on) {
		sleep(1);
	}

	RT_LOG_I(TAG, "OUT : %s", __func__);
}

static void dummy_func(void *data)
{
	// do nothing. it makes rt_thread_terminate() call pthread_join
	return;
}

static void stop_mock_server(void)
{
	RT_LOG_I(TAG, "IN : %s", __func__);
	g_terminated = 1;
	g_server_on = 0;
	mbedtls_net_free(&client_fd);
	mbedtls_net_free(&listen_fd);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ssl_cookie_free(&cookie_ctx);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);

	rt_thread_terminate(&tid, dummy_func, NULL);

	RT_LOG_I(TAG, "OUT : %s", __func__);
}

static void *dtls_server_runner(void *args)
{
	int result;
	dtls_server_init();
	if (RESULT_ERROR == dtls_server_bind()) {
		goto exit;
	}

	if (RESULT_ERROR == dtls_server_generate_seeding_random_number()) {
		goto exit;
	}

	if (RESULT_ERROR == dtls_server_set_dtls_data()) {
		goto exit;
	}

reset:
	dtls_server_reset();
	result = dtls_server_wait_client();
	if (RESULT_RESET == result) {
		goto reset;
	}
	if (RESULT_ERROR == result) {
		goto exit;
	}

	result = dtls_server_handshake();
	if (RESULT_RESET == result) {
		goto reset;
	}
	sleep(1);
	if (RESULT_ERROR == result) {
		goto exit;
	}
	if (g_is_handshaketest == 1) {
		goto reset;
	}

	result = dtls_server_read_request();
	if (RESULT_RESET == result) {
		goto reset;
	}
	if (RESULT_CLOSE_NOTIFY == result) {
		pthread_mutex_lock(&g_mutex);
		pthread_cond_signal(&g_close_notify_condition);
		pthread_mutex_unlock(&g_mutex);
		goto exit;
	}
	if (RESULT_ERROR == result) {
		goto exit;
	}

	result = dtls_server_write_response();
	if (RESULT_ERROR == result) {
		goto exit;
	}
	if (result == RESULT_OK) {
		goto reset;
	}
exit:
	return NULL;
}

static void dtls_server_init(void)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	mbedtls_ssl_init(&ssl);
	RT_LOG_D(TAG, "OUT : %s", __func__);
}

static int dtls_server_bind(void)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	int ret = -1;

	listen_fd.fd = socket(PF_INET, SOCK_DGRAM, 0);

	struct sockaddr_in addr;
	socklen_t socket_len = sizeof(addr);

	if ((ret = mbedtls_net_bind(&listen_fd, NULL, "0", MBEDTLS_NET_PROTO_UDP)) != 0) {
		RT_LOG_D(TAG, " failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
		return RESULT_ERROR;
	}

	if (-1 == getsockname(listen_fd.fd, (struct sockaddr *)&addr, &socket_len)) {
		RT_LOG_E(TAG, "getsockname failaed");
		return -1;
	}
	g_test_port = ntohs(((struct sockaddr_in *)&addr)->sin_port);
	RT_LOG_D(TAG, "Dtls Server Port:[[[%d]]] ...", g_test_port);

	RT_LOG_D(TAG, "OUT : %s", __func__);
	return RESULT_OK;
}

static int dtls_server_generate_seeding_random_number(void)
{
	int ret = -1;
	RT_LOG_D(TAG, "IN : %s", __func__);
	RT_LOG_D(TAG, "  . Seeding the random number generator...");
	if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers))) != 0) {
		RT_LOG_D(TAG, " failed\n  ! mbedtls_ctr_drbg_seed returned %d\n", ret);
		return RESULT_ERROR;
	}
	RT_LOG_D(TAG, "OUT : %s", __func__);
	return RESULT_OK;
}

static int dtls_server_set_dtls_data(void)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	int ret = -1;
	RT_LOG_D(TAG, "  . Setting up the DTLS data...");

	if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_SERVER, MBEDTLS_SSL_TRANSPORT_DATAGRAM, MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
		RT_LOG_D(TAG, " failed\n  ! mbedtls_ssl_config_defaults returned %d\n\n", ret);
		return RESULT_ERROR;
	}

	mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
	mbedtls_ssl_conf_dbg(&conf, my_debug, stdout);

	if ((ret = mbedtls_ssl_cookie_setup(&cookie_ctx, mbedtls_ctr_drbg_random, &ctr_drbg)) != 0) {
		RT_LOG_D(TAG, " failed\n  ! mbedtls_ssl_cookie_setup returned %d\n\n", ret);
		return RESULT_ERROR;
	}

	mbedtls_ssl_conf_dtls_cookies(&conf, mbedtls_ssl_cookie_write, mbedtls_ssl_cookie_check, &cookie_ctx);

	if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
		RT_LOG_D(TAG, " failed\n  ! mbedtls_ssl_setup returned %d\n\n", ret);
		return RESULT_ERROR;
	}

	mbedtls_ssl_set_timer_cb(&ssl, &timer, mbedtls_timing_set_delay, mbedtls_timing_get_delay);
	mbedtls_ssl_conf_ciphersuites(&conf, g_test_ciphersuit_list);
	RT_LOG_D(TAG, "OUT : %s", __func__);
	return RESULT_OK;
}

static void dtls_server_reset(void)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	mbedtls_net_free(&client_fd);
	mbedtls_ssl_session_reset(&ssl);
	RT_LOG_D(TAG, "OUT : %s", __func__);
}

static int dtls_server_wait_client(void)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	int ret = -1;
	struct timeval timeout;
	int i, counts;
	RT_LOG_D(TAG, "  . Waiting for a remote connection ...");
	g_server_on = 1;

	if (listen_fd.fd < 0) {
		return RESULT_ERROR;
	}

	fd_set read_sock_set, selected_sock_set;
	FD_ZERO(&read_sock_set);
	FD_SET(listen_fd.fd, &read_sock_set);

	while (!g_terminated) {
		int is_received = 0;
		timeout.tv_sec = SELECT_TIME_SEC;
		timeout.tv_usec = 0;

		selected_sock_set = read_sock_set;
		counts = select(FD_SETSIZE, &selected_sock_set, NULL, NULL, &timeout);

		for (i = 0; i < counts; i++) {
			if (FD_ISSET(listen_fd.fd, &selected_sock_set)) {
				if ((ret = mbedtls_net_accept(&listen_fd, &client_fd, client_ip, sizeof(client_ip), &cliip_len)) != 0) {
					RT_LOG_D(TAG, " failed  ! mbedtls_net_accept returned %d\n\n", ret);
					return RESULT_ERROR;
				}
				FD_CLR(listen_fd.fd, &selected_sock_set);
				is_received = 1;
			}
		}
		if (is_received) {
			break;
		}
	}

	/* For HelloVerifyRequest cookies */
	if ((ret = mbedtls_ssl_set_client_transport_id(&ssl, client_ip, cliip_len)) != 0) {
		RT_LOG_D(TAG, " failed\n  ! " "mbedtls_ssl_set_client_transport_id() returned -0x%x\n\n", -ret);
		return RESULT_ERROR;
	}
	mbedtls_ssl_set_bio(&ssl, &client_fd, mbedtls_net_send, mbedtls_net_recv, mbedtls_net_recv_timeout);
	RT_LOG_D(TAG, "OUT : %s", __func__);
	return RESULT_OK;
}

static int dtls_server_handshake(void)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	int ret = -1;
	RT_LOG_D(TAG, "  . Performing the DTLS handshake...");

	do {
		ret = mbedtls_ssl_handshake(&ssl);
	} while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	if (ret == MBEDTLS_ERR_SSL_HELLO_VERIFY_REQUIRED) {
		RT_LOG_D(TAG, " hello verification requested\n");
		ret = 0;
		return RESULT_RESET;
	} else if (ret != 0) {
		RT_LOG_D(TAG, " failed\n  ! mbedtls_ssl_handshake returned -0x%x\n\n", -ret);
		return RESULT_RESET;
	}

	RT_LOG_D(TAG, "OUT : %s", __func__);
	return RESULT_OK;
}

static int dtls_server_read_request(void)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	int ret = -1;
	len = sizeof(buf) - 1;
	memset(buf, 0, sizeof(buf));

	do {
		ret = mbedtls_ssl_read(&ssl, buf, len);
	} while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	if (ret <= 0) {
		switch (ret) {
		case MBEDTLS_ERR_SSL_TIMEOUT:
			RT_LOG_D(TAG, " timeout\n\n");
			return RESULT_ERROR;

		case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
			RT_LOG_D(TAG, " connection was closed gracefully\n");
			ret = 0;
			return RESULT_CLOSE_NOTIFY;

		default:
			RT_LOG_D(TAG, " mbedtls_ssl_read returned -0x%x\n", -ret);
			return RESULT_ERROR;
		}
	}

	len = ret;
	RT_LOG_D(TAG, " < READ FROM CLIENT %d bytes read : %s\n", len, buf);
	RT_LOG_D(TAG, "OUT : %s", __func__);
	return RESULT_OK;
}

static int dtls_server_write_response(void)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	int ret = -1;
	do {
		ret = mbedtls_ssl_write(&ssl, buf, len);
	} while (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE);

	if (ret < 0) {
		RT_LOG_D(TAG, " failed\n  ! mbedtls_ssl_write returned %d\n", ret);
		return RESULT_ERROR;
	}

	len = ret;
	RT_LOG_D(TAG, " > WRITE TO CLIENT %d bytes written : %s\n", len, buf);
	RT_LOG_D(TAG, "OUT : %s", __func__);
	return RESULT_OK;
}

static int dtls_server_close_notify(void)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	int ret = -1;
	RT_LOG_D(TAG, "  . Closing the connection...");
	/* No error checking, the connection might be closed already */
	do {
		ret = mbedtls_ssl_close_notify(&ssl);
	} while (ret == MBEDTLS_ERR_SSL_WANT_WRITE);
	ret = 0;

	RT_LOG_D(TAG, "OUT : %s", __func__);
	return RESULT_OK;
}

static void dtls_server_terminate(void)
{
	RT_LOG_D(TAG, "IN : %s", __func__);
	mbedtls_net_free(&client_fd);
	mbedtls_net_free(&listen_fd);
	mbedtls_ssl_free(&ssl);
	mbedtls_ssl_config_free(&conf);
	mbedtls_ssl_cookie_free(&cookie_ctx);
	mbedtls_ctr_drbg_free(&ctr_drbg);
	mbedtls_entropy_free(&entropy);
	RT_LOG_D(TAG, "OUT : %s", __func__);
}
