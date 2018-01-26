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
#include "Mocksocket.h"
#include "Mockselect.h"

#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>

#include "ocf_types.h"
#include "rt_transport.h"
#include "rt_logger.h"
#include "rt_endpoint.h"
#include "test_common.h"

#define TAG "TC_TRANSPORT_MOCK"

static pthread_cond_t g_rt_transport_receive_packet_cond;
static pthread_cond_t g_rt_transport_send_packet_cond;
static pthread_mutex_t g_send_mutex;
static pthread_mutex_t g_receive_mutex;

TEST_GROUP(test_transport_mock);

TEST_SETUP(test_transport_mock)
{
	select_IgnoreAndReturn(0);
	rt_random_init();
	rt_mem_pool_init();
	rt_transport_init();
	Mocksocket_Init();
	pthread_mutex_init(&g_send_mutex, NULL);
	pthread_mutex_init(&g_receive_mutex, NULL);
	pthread_cond_init(&g_rt_transport_send_packet_cond, NULL);
	pthread_cond_init(&g_rt_transport_receive_packet_cond, NULL);
}

TEST_TEAR_DOWN(test_transport_mock)
{
	pthread_cond_destroy(&g_rt_transport_send_packet_cond);
	pthread_cond_destroy(&g_rt_transport_receive_packet_cond);
	pthread_mutex_destroy(&g_send_mutex);
	pthread_mutex_destroy(&g_receive_mutex);
	rt_transport_terminate();
	rt_mem_pool_terminate();
	Mocksocket_Verify();
	Mocksocket_Destroy();
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
	pthread_mutex_t *mutex = NULL;

	if (cond == &g_rt_transport_send_packet_cond) {
		mutex = &g_send_mutex;
	} else if (cond == &g_rt_transport_receive_packet_cond) {
		mutex = &g_receive_mutex;
	} else {
		return -1;
	}

	pthread_mutex_lock(mutex);
	struct timespec ts;
	get_wait_timespec(&ts);
	int ret = pthread_cond_timedwait(cond, mutex, &ts);
	pthread_mutex_unlock(mutex);
	return ret;
}

static ssize_t sendto_callback(int __fd, const void *__buf, size_t __n, int __flags, __CONST_SOCKADDR_ARG __addr, socklen_t __addr_len, int cmock_num_calls)
{
	TEST_ASSERT_EQUAL_STRING_LEN("ABCDE", __buf, __n);
	TEST_ASSERT_EQUAL_INT(5, __n);

	pthread_mutex_lock(&g_send_mutex);
	pthread_cond_signal(&g_rt_transport_send_packet_cond);
	pthread_mutex_unlock(&g_send_mutex);
	return 5;
}

TEST(test_transport_mock, MOCK_transport_send_unicast_packet)
{
	// Given
	// packet과, socket_fd, endPoint를 설정한다.
	// Mock과 관련된 설정을 한다.
	const char *payload = "ABCDE";
	uint16_t dataSize = 5;
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 5555, OCF_DEFAULT_FLAGS | OCF_UDP | OCF_IPV4);

	sendto_StubWithCallback(sendto_callback);
	sendto_ExpectAndReturn(0, (uint8_t *) payload, dataSize, 0, NULL, 0, 5);
	sendto_IgnoreArg___fd();
	sendto_IgnoreArg___addr();
	sendto_IgnoreArg___addr_len();

	// When
	// msg_send_packet을 호출한다.
	ocf_result_t res = rt_transport_send_packet((uint8_t *) payload, dataSize, &endpoint);
	TEST_ASSERT_EQUAL_INT(OCF_OK, res);

	// Then
	// sendto가 주어진 packet, socket_fd로 보내진다.
	// sendto에 전달된 remote_addr에 endPoint로 전달한 value가 들어있다.
	int ret = wait_condition(&g_rt_transport_send_packet_cond);
	TEST_ASSERT_EQUAL_INT(0, ret);
}

TEST(test_transport_mock, MOCK_transport_send_multicast_packet)
{
	// Given
	// packet과, socket_fd, endPoint를 설정한다.
	// Mock과 관련된 설정을 한다.
	const char *payload = "ABCDE";
	uint16_t dataSize = 5;

	sendto_StubWithCallback(sendto_callback);
	sendto_ExpectAndReturn(0, (uint8_t *) payload, dataSize, 0, NULL, 0, 5);
	sendto_IgnoreArg___fd();
	sendto_IgnoreArg___addr();
	sendto_IgnoreArg___addr_len();

	// When
	// msg_send_packet을 호출한다.
	ocf_result_t res = rt_transport_send_packet((uint8_t *) payload, dataSize, NULL);
	TEST_ASSERT_EQUAL_INT(OCF_OK, res);

	// Then
	// sendto가 주어진 packet, socket_fd로 보내진다.
	// sendto에 전달된 remote_addr에 endPoint로 전달한 value가 들어있다.
	int ret = wait_condition(&g_rt_transport_send_packet_cond);
	TEST_ASSERT_EQUAL_INT(0, ret);
}

static void recv_handler(uint8_t *packet, uint16_t len, const ocf_endpoint_s *endpoint)
{
	RT_LOG_D(TAG, "%s", __func__);
	TEST_ASSERT_EQUAL_STRING_LEN("ABCDE", packet, len);
	TEST_ASSERT_EQUAL_INT(5, len);

	pthread_mutex_lock(&g_receive_mutex);
	pthread_cond_signal(&g_rt_transport_receive_packet_cond);
	pthread_mutex_unlock(&g_receive_mutex);
}

static int select_success_callback(int __nfds, fd_set *__restrict __readfds, fd_set *__restrict __writefds, fd_set *__restrict __exceptfds, struct timeval *__restrict __timeout, int cmock_num_calls)
{
	RT_LOG_D(TAG, "select callback called!");
	int udp_ucast_fd = -1;

	FD_ZERO(__readfds);
	rt_udp_get_normal_sock_v4(&udp_ucast_fd);
	FD_SET(udp_ucast_fd, __readfds);
	select_IgnoreAndReturn(0);
	usleep(100 * 1000);
	return 1;
}

static ssize_t recvfrom_callback(int __fd, void *__restrict __buf, size_t __n, int __flags, __SOCKADDR_ARG __addr, socklen_t *__restrict __addr_len, int cmock_num_calls)
{
	RT_LOG_D(TAG, "recvfrom_callback called!");
	const char *payload = "ABCDE";
	uint16_t dataSize = 5;

	memcpy(__buf, payload, dataSize);

	__addr.__sockaddr_in__->sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &(__addr.__sockaddr_in__->sin_addr.s_addr));
	__addr.__sockaddr_in__->sin_port = htons(5555);

	return dataSize;
}

TEST(test_transport_mock, MOCK_transport_receive_udp_packet)
{
	// Given
	rt_transport_set_receive_handler(recv_handler);

	select_StubWithCallback(select_success_callback);
	recvfrom_StubWithCallback(recvfrom_callback);
	// When
	// msg_send_packet을 호출한다.
	// rt_transport_send_unicast((uint8_t *) payload, dataSize, &endpoint);
	int ret = wait_condition(&g_rt_transport_receive_packet_cond);
	TEST_ASSERT_EQUAL_INT(0, ret);
}

static int connect_success_callback(int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len, int cmock_num_calls)
{
	RT_LOG_D(TAG, "connect callback called!");
	char buf[40];
	inet_ntop(AF_INET, &(__addr.__sockaddr_in__->sin_addr.s_addr), buf, sizeof(buf));
	TEST_ASSERT_EQUAL_STRING("127.0.0.1", buf);
	TEST_ASSERT_EQUAL_INT(5555, ntohs(__addr.__sockaddr_in__->sin_port));
	return 0;
}

static ssize_t send_callback(int __fd, const void *__buf, size_t __n, int __flags, int cmock_num_calls)
{
	RT_LOG_D(TAG, "send callback called!");
	TEST_ASSERT_EQUAL_STRING_LEN("ABCDE", __buf, __n);
	TEST_ASSERT_EQUAL_INT(5, __n);

	pthread_mutex_lock(&g_send_mutex);
	pthread_cond_signal(&g_rt_transport_send_packet_cond);
	pthread_mutex_unlock(&g_send_mutex);
	return 5;
}

TEST(test_transport_mock, MOCK_transport_tcp_send_packet)
{
	// Given
	// packet과, socket_fd, endPoint를 설정한다.
	// Mock과 관련된 설정을 한다.
	const char *payload = "ABCDE";
	uint16_t dataSize = 5;
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, "127.0.0.1", 5555, OCF_TCP | OCF_IPV4);

	connect_StubWithCallback(connect_success_callback);
	send_StubWithCallback(send_callback);

	// When
	// msg_send_packet을 호출한다.
	ocf_result_t res = rt_transport_send_packet((uint8_t *) payload, dataSize, &endpoint);
	TEST_ASSERT_EQUAL_INT(OCF_OK, res);

	// Then
	// sendto가 주어진 packet, socket_fd로 보내진다.
	// sendto에 전달된 remote_addr에 endPoint로 전달한 값이 들어있다.
	int ret = wait_condition(&g_rt_transport_send_packet_cond);
	TEST_ASSERT_EQUAL_INT(0, ret);
}

static int client_socket = 27;
static int select_recv_callback(int __nfds, fd_set *__restrict __readfds, fd_set *__restrict __writefds, fd_set *__restrict __exceptfds, struct timeval *__restrict __timeout, int cmock_num_calls)
{
	RT_LOG_D(TAG, "select_recv_callback callback called!");
	FD_ZERO(__readfds);
	FD_SET(client_socket, __readfds);
	select_IgnoreAndReturn(0);
	usleep(100 * 1000);
	return 1;
}

static int select_accept_callback(int __nfds, fd_set *__restrict __readfds, fd_set *__restrict __writefds, fd_set *__restrict __exceptfds, struct timeval *__restrict __timeout, int cmock_num_calls)
{
	int tcp_ucast_fd = -1;

	RT_LOG_D(TAG, "select_accept_callback callback called!");
	FD_ZERO(__readfds);
	rt_tcp_get_normal_sock_v4(&tcp_ucast_fd);
	FD_SET(tcp_ucast_fd, __readfds);
	select_StubWithCallback(select_recv_callback);
	usleep(100 * 1000);
	return 1;
}

int accecpt_callback(int __fd, __SOCKADDR_ARG __addr, socklen_t *__restrict __addr_len, int cmock_num_calls)
{
	RT_LOG_D(TAG, "accecpt_callback callback called!");
	__addr.__sockaddr_in__->sin_family = AF_INET;
	inet_pton(AF_INET, "127.0.0.1", &(__addr.__sockaddr_in__->sin_addr.s_addr));
	__addr.__sockaddr_in__->sin_port = htons(5555);

	return client_socket;
}

ssize_t recv_callback(int __fd, void *__buf, size_t __n, int __flags, int cmock_num_calls)
{
	RT_LOG_D(TAG, "recv_callback callback called!");
	TEST_ASSERT_EQUAL_INT(client_socket, __fd);
	const char *payload = "ABCDE";
	uint16_t dataSize = 5;

	memcpy(__buf, payload, dataSize);

	return dataSize;
}

TEST(test_transport_mock, MOCK_transport_receive_tcp_packet)
{
	// Given
	rt_transport_set_receive_handler(recv_handler);

	select_StubWithCallback(select_accept_callback);
	accept_StubWithCallback(accecpt_callback);
	recv_StubWithCallback(recv_callback);

	// When
	// msg_send_packet을 호출한다.
	// rt_transport_send_unicast((uint8_t *) payload, dataSize, &endpoint);
	int ret = wait_condition(&g_rt_transport_receive_packet_cond);
	TEST_ASSERT_EQUAL_INT(0, ret);
}

TEST_GROUP_RUNNER(test_transport_mock)
{
	RUN_TEST_CASE(test_transport_mock, MOCK_transport_send_unicast_packet);
	RUN_TEST_CASE(test_transport_mock, MOCK_transport_send_multicast_packet);
	RUN_TEST_CASE(test_transport_mock, MOCK_transport_receive_udp_packet);
	RUN_TEST_CASE(test_transport_mock, MOCK_transport_tcp_send_packet);
	RUN_TEST_CASE(test_transport_mock, MOCK_transport_receive_tcp_packet);
}

#ifndef CONFIG_ENABLE_RT_OCF

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_transport_mock);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
