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

#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <arpa/inet.h>

#include "rt_logger.h"
#include "rt_udp.h"
#include "rt_endpoint.h"
#include "rt_coap.h"

#define INVALID_SOCKET (-1)

#define MULTICAST_PORT_V4 5683
#define MULTICAST_ADDR_V4 "224.0.1.187"

static const char *TAG = "RT_UDP";

struct udp_sock_s {
	int mcast_v4, ucast_v4, dtls_v4;
	int mcast_v6, ucast_v6, dtls_v6;
};

struct udp_sock_s udp_socket = {
	INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET,
	INVALID_SOCKET, INVALID_SOCKET, INVALID_SOCKET
};

static void rt_udp_close_server(void)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	if (INVALID_SOCKET != udp_socket.mcast_v4) {
		close(udp_socket.mcast_v4);
		udp_socket.mcast_v4 = INVALID_SOCKET;
	}

	if (INVALID_SOCKET != udp_socket.ucast_v4) {
		close(udp_socket.ucast_v4);
		udp_socket.ucast_v4 = INVALID_SOCKET;
	}

	if (INVALID_SOCKET != udp_socket.dtls_v4) {
		close(udp_socket.dtls_v4);
		udp_socket.dtls_v4 = INVALID_SOCKET;
	}

	RT_LOG_D(TAG, "%s OUT", __func__);
}

static int rt_udp_set_multicast_option(int sock_fd)
{
	/* use setsockopt() to request that the kernel join a multicast group */
	struct ip_mreq mreq  = { .imr_multiaddr.s_addr = inet_addr(MULTICAST_ADDR_V4),
		.imr_interface.s_addr = htonl(INADDR_ANY) };
	if (INVALID_SOCKET == setsockopt(sock_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) {
		RT_LOG_E(TAG, "setsockopt failed(IP_ADD_MEMBERSHIP)");
		return OCF_ERROR;
	}

	/* use setsockopt() to request that the kernel reuses multicast address */
	int on = 1;
	if (INVALID_SOCKET == setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
		RT_LOG_E(TAG, "setsockopt failed(SO_REUSEADDR)");
		return OCF_ERROR;
	}

	if (-1 == setsockopt(sock_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &on, sizeof(on))) {
		RT_LOG_E(TAG, "setsockopt failed(IP_MULTICAST_LOOP)");
		return OCF_ERROR;
	}

	return OCF_OK;
}

static ocf_result_t rt_udp_get_assigned_port(int sock_fd, uint16_t *port)
{
	struct sockaddr_in addr;
	socklen_t len = sizeof(addr);
	if (INVALID_SOCKET == getsockname(sock_fd, (struct sockaddr *)&addr, &len)) {
		RT_LOG_E(TAG, "getsockname failaed");
		return OCF_ERROR;
	}
	*port = ntohs(((struct sockaddr_in *)&addr)->sin_port);

	return OCF_OK;
}

static int rt_udp_set_socket_bind_specific_port(int sock_fd, int is_v4, uint16_t port)
{
	struct sockaddr_in addr;

	memset(&addr, 0, sizeof(addr));
	if (is_v4) {
		addr.sin_family = AF_INET;
	} else {
		addr.sin_family = AF_INET;	//TODO: change to ipv6
	}

	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	addr.sin_port = htons(port);

	if (INVALID_SOCKET == bind(sock_fd, (const struct sockaddr *)&addr, sizeof(addr))) {
		RT_LOG_D(TAG, "bind failed");
		rt_udp_close_server();
		return OCF_ERROR;
	}

	return OCF_OK;
}

static int rt_udp_open_server(void)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	if (INVALID_SOCKET != udp_socket.mcast_v4 || INVALID_SOCKET != udp_socket.ucast_v4 || INVALID_SOCKET != udp_socket.dtls_v4) {
		RT_LOG_D(TAG, "socket is already created!");
		return OCF_ERROR;
	}

	udp_socket.mcast_v4 = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	udp_socket.ucast_v4 = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
	udp_socket.dtls_v4 = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);

	if (INVALID_SOCKET == udp_socket.mcast_v4 || INVALID_SOCKET == udp_socket.ucast_v4 || INVALID_SOCKET == udp_socket.dtls_v4) {
		RT_LOG_E(TAG, "socket create failed!");
		return OCF_ERROR;
	}
	RT_LOG_D(TAG, "Socket has been created.");

	if (OCF_OK != rt_udp_set_multicast_option(udp_socket.mcast_v4)) {
		RT_LOG(OCF_LOG_ERROR, TAG, "rt_udp_set_multicast_option failed");
		rt_udp_close_server();
		return OCF_ERROR;
	}

	if (OCF_OK != rt_udp_set_socket_bind_specific_port(udp_socket.mcast_v4, 1, MULTICAST_PORT_V4)) {
		RT_LOG(OCF_LOG_ERROR, TAG, "rt_udp_set_socket_bind_specific_port failed for udp_socket.mcast_v4");
		rt_udp_close_server();
		return OCF_ERROR;
	}

	if (OCF_OK != rt_udp_set_socket_bind_specific_port(udp_socket.ucast_v4, 1, 0)) {
		RT_LOG(OCF_LOG_ERROR, TAG, "rt_udp_set_socket_bind_specific_port failed for udp_socket.ucast_v4");
		rt_udp_close_server();
		return OCF_ERROR;
	}

	if (OCF_OK != rt_udp_set_socket_bind_specific_port(udp_socket.dtls_v4, 1, 0)) {
		RT_LOG(OCF_LOG_ERROR, TAG, "rt_udp_set_socket_bind_specific_port failed for udp_socket.dtls_v4");
		rt_udp_close_server();
		return OCF_ERROR;
	}

	uint16_t port;
	rt_udp_get_assigned_port(udp_socket.ucast_v4, &port);
	RT_LOG_I(TAG, "UDP ipv4_normal_port : %d", port);
	rt_udp_get_assigned_port(udp_socket.dtls_v4, &port);
	RT_LOG_I(TAG, "UDP ipv4_dtls_port : %d", port);

	RT_LOG_D(TAG, "%s OUT", __func__);
	return OCF_OK;
}

ocf_result_t rt_udp_receive_message(fd_set *fds, uint8_t *packet, uint16_t *len, ocf_endpoint_s *endpoint)
{
	struct sockaddr_in fromAddr;
	socklen_t fromAddrSize = sizeof(fromAddr);

	RT_LOG_D(TAG, "%s IN", __func__);

	if (udp_socket.mcast_v4 != INVALID_SOCKET && FD_ISSET(udp_socket.mcast_v4, fds)) {
		*len = recvfrom(udp_socket.mcast_v4, packet, COAP_MAX_PACKET_SIZE, 0, (struct sockaddr *)&fromAddr, &fromAddrSize);

		endpoint->flags |= OCF_MULTICAST | OCF_IPV4 | OCF_UDP;
		FD_CLR(udp_socket.mcast_v4, fds);
	} else if (udp_socket.ucast_v4 != INVALID_SOCKET && FD_ISSET(udp_socket.ucast_v4, fds)) {
		*len = recvfrom(udp_socket.ucast_v4, packet, COAP_MAX_PACKET_SIZE, 0, (struct sockaddr *)&fromAddr, &fromAddrSize);

		endpoint->flags |= OCF_IPV4 | OCF_UDP;
		FD_CLR(udp_socket.ucast_v4, fds);
	} else if (udp_socket.dtls_v4 != INVALID_SOCKET && FD_ISSET(udp_socket.dtls_v4, fds)) {
		*len = recvfrom(udp_socket.dtls_v4, packet, COAP_MAX_PACKET_SIZE, 0, (struct sockaddr *)&fromAddr, &fromAddrSize);

		endpoint->flags |= OCF_SECURE | OCF_IPV4 | OCF_UDP;
		FD_CLR(udp_socket.dtls_v4, fds);
	} else {
		return OCF_CONTINUE;
	}

	endpoint->addr[0] = fromAddr.sin_addr.s_addr;
	endpoint->port = ntohs(fromAddr.sin_port);

	return OCF_OK;
}

void rt_udp_set_fds(fd_set *sock_set)
{
	if (INVALID_SOCKET != udp_socket.mcast_v4) {
		FD_SET(udp_socket.mcast_v4, sock_set);
	}
	if (INVALID_SOCKET != udp_socket.ucast_v4) {
		FD_SET(udp_socket.ucast_v4, sock_set);
	}
	if (INVALID_SOCKET != udp_socket.dtls_v4) {
		FD_SET(udp_socket.dtls_v4, sock_set);
	}
}

ocf_result_t rt_udp_init(void)
{
	if (OCF_OK != rt_udp_open_server()) {
		return OCF_ERROR;
	}

	return OCF_OK;
}

ocf_result_t rt_udp_terminate(void)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	rt_udp_close_server();
	RT_LOG_D(TAG, "%s OUT", __func__);

	return OCF_OK;
}

static ocf_result_t rt_udp_send_packet(const uint8_t *packet, uint16_t len, int sock_fd, const ocf_endpoint_s *endpoint)
{
	struct sockaddr_in remote_addr;
	RT_LOG_D(TAG, "%s IN", __func__);
	rt_endpoint_log(OCF_LOG_INFO, TAG, endpoint);

	if (INVALID_SOCKET == sock_fd) {
		RT_LOG_D(TAG, "Invalid socket(%d)", sock_fd);
		return OCF_COMM_ERROR;
	}

	memset(&remote_addr, 0, sizeof(remote_addr));
	remote_addr.sin_family = AF_INET;
	remote_addr.sin_addr.s_addr = endpoint->addr[0];
	remote_addr.sin_port = htons(endpoint->port);

	if (0 > sendto(sock_fd, packet, len, 0, (const struct sockaddr *)&remote_addr, sizeof(remote_addr))) {
		RT_LOG_E(TAG, "sendto failed");
		return OCF_COMM_ERROR;
	}
	RT_LOG_I(TAG, "send %i Bytes success!", len);
	RT_LOG_D(TAG, "%s OUT", __func__);

	return OCF_OK;
}

ocf_result_t rt_udp_send_unicast(const uint8_t *packet, uint16_t len, const ocf_endpoint_s *endpoint)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	ocf_result_t res = OCF_ERROR;
	int sock_fd = endpoint->flags & OCF_SECURE ? udp_socket.dtls_v4 : udp_socket.ucast_v4;

	res = rt_udp_send_packet(packet, len, sock_fd, endpoint);
	RT_LOG_D(TAG, "%s OUT", __func__);

	return res;
}

ocf_result_t rt_udp_send_multicast(const uint8_t *packet, uint16_t len)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	ocf_result_t res = OCF_ERROR;
	ocf_endpoint_s endpoint;
	rt_endpoint_set(&endpoint, MULTICAST_ADDR_V4, MULTICAST_PORT_V4, OCF_IPV4 | OCF_MULTICAST);

	int sock_fd = udp_socket.ucast_v4;

	int on = 1;
	if (-1 == setsockopt(sock_fd, IPPROTO_IP, IP_MULTICAST_LOOP, &on, sizeof(on))) {
		RT_LOG_E(TAG, "setsockopt failed(IP_MULTICAST_LOOP)");
		return OCF_ERROR;
	}

	res = rt_udp_send_packet(packet, len, sock_fd, &endpoint);
	RT_LOG_D(TAG, "%s OUT", __func__);
	return res;
}

ocf_result_t rt_udp_get_secure_port_v4(uint16_t *port)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	if (OCF_OK != rt_udp_get_assigned_port(udp_socket.dtls_v4, port)) {
		return OCF_ERROR;
	}
	RT_LOG_D(TAG, "DTLS_port: %d", *port);
	RT_LOG_D(TAG, "%s OUT", __func__);
	return OCF_OK;
}

void rt_udp_get_secure_sock_v4(int *dtls_fd)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	*dtls_fd = udp_socket.dtls_v4;
	RT_LOG_D(TAG, "%s OUT", __func__);
}

ocf_result_t rt_udp_get_normal_port_v4(uint16_t *port)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	if (OCF_OK != rt_udp_get_assigned_port(udp_socket.ucast_v4, port)) {
		return OCF_ERROR;
	}
	RT_LOG_D(TAG, "UDP_port: %d", *port);
	RT_LOG_D(TAG, "%s OUT", __func__);
	return OCF_OK;
}

void rt_udp_get_normal_sock_v4(int *udp_v4_normal_fd)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	*udp_v4_normal_fd = udp_socket.ucast_v4;
	RT_LOG_D(TAG, "%s OUT", __func__);
}
