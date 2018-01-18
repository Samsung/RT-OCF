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
#include "rt_mem.h"
#include "rt_list.h"
#include "rt_tcp.h"
#include "rt_endpoint.h"

#define INVALID_SOCKET (-1)
#define RT_TCP_LISTEN_BACKLOG  3

static const char *TAG = "RT_TCP";

struct tcp_sock_s {
	int ucast_v4, tls_v4;
	int ucast_v6, tls_v6;
};

typedef struct {
	ocf_endpoint_s endpoint;
	int sock_fd;
	// state?
	rt_node_s node;
} rt_tcp_svr_s;

static rt_list_s svr_list;
static struct tcp_sock_s tcp_socket = {
	INVALID_SOCKET, INVALID_SOCKET,
	INVALID_SOCKET, INVALID_SOCKET
};

static void rt_tcp_close_server(void)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	if (INVALID_SOCKET != tcp_socket.ucast_v4) {
		close(tcp_socket.ucast_v4);
		tcp_socket.ucast_v4 = INVALID_SOCKET;
	}

	if (INVALID_SOCKET != tcp_socket.tls_v4) {
		close(tcp_socket.tls_v4);
		tcp_socket.tls_v4 = INVALID_SOCKET;
	}

	RT_LOG_D(TAG, "%s OUT", __func__);
}

static ocf_result_t rt_tcp_get_assigned_port(int sock_fd, uint16_t *port)
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

static int rt_tcp_set_socket_bind_specific_port(int sock_fd, int is_v4, uint16_t port)
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

	/* use setsockopt() to request that the kernel reues multicast address */
	int on = 1;
	if (INVALID_SOCKET == setsockopt(sock_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on))) {
		RT_LOG_E(TAG, "setsockopt failed(SO_REUSEADDR)");
		return OCF_ERROR;
	}

	if (INVALID_SOCKET == bind(sock_fd, (const struct sockaddr *)&addr, sizeof(addr))) {
		RT_LOG_D(TAG, "bind failed");
		rt_tcp_close_server();
		return OCF_ERROR;
	}

	if (0 != listen(sock_fd, RT_TCP_LISTEN_BACKLOG)) {
		RT_LOG_D(TAG, "listen error");
		rt_tcp_close_server();
		return OCF_ERROR;
	}

	return OCF_OK;
}

static int rt_tcp_open_server(void)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	if (INVALID_SOCKET != tcp_socket.ucast_v4 || INVALID_SOCKET != tcp_socket.tls_v4) {
		RT_LOG_D(TAG, "socket is already created!");
		return OCF_ERROR;
	}

	tcp_socket.ucast_v4 = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
	tcp_socket.tls_v4 = socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);

	if (INVALID_SOCKET == tcp_socket.ucast_v4 || INVALID_SOCKET == tcp_socket.tls_v4) {
		RT_LOG_E(TAG, "socket create failed!");
		return OCF_ERROR;
	}
	RT_LOG_D(TAG, "Socket has been created.");

	if (OCF_OK != rt_tcp_set_socket_bind_specific_port(tcp_socket.ucast_v4, 1, 0)) {
		RT_LOG(OCF_LOG_ERROR, TAG, "rt_tcp_set_socket_bind_specific_port failed for tcp_socket.ucast_v4");
		rt_tcp_close_server();
		return OCF_ERROR;
	}

	if (OCF_OK != rt_tcp_set_socket_bind_specific_port(tcp_socket.tls_v4, 1, 0)) {
		RT_LOG(OCF_LOG_ERROR, TAG, "rt_tcp_set_socket_bind_specific_port failed for tcp_socket.tls_v4");
		rt_tcp_close_server();
		return OCF_ERROR;
	}
	uint16_t port = 0;
	rt_tcp_get_assigned_port(tcp_socket.ucast_v4, &port);
	RT_LOG(OCF_LOG_DEBUG, TAG, "TCP ipv4_normal_port : %d", port);
	rt_tcp_get_assigned_port(tcp_socket.tls_v4, &port);
	RT_LOG(OCF_LOG_DEBUG, TAG, "TCP ipv4_tls_port : %d", port);

	RT_LOG_D(TAG, "%s OUT", __func__);
	return OCF_OK;
}

static ocf_result_t rt_tcp_accept_message(int fd, fd_set *fds)
{
	struct sockaddr_in fromAddr;
	socklen_t fromAddrSize = sizeof(fromAddr);

	int sock_fd = accept(fd, (struct sockaddr *)&fromAddr, &fromAddrSize);
	if (INVALID_SOCKET == sock_fd) {
		RT_LOG_E(TAG, "accept failed");
		return OCF_COMM_ERROR;
	}
	RT_LOG_I(TAG, "accept success");

	rt_tcp_svr_s *svr = (rt_tcp_svr_s *) rt_mem_alloc(sizeof(rt_tcp_svr_s));
	if (!svr) {
		RT_LOG_E(TAG, "svr alloc failed");
		close(sock_fd);
		return OCF_MEM_FULL;
	}

	svr->endpoint.addr[0] = fromAddr.sin_addr.s_addr;
	svr->endpoint.port = ntohs(fromAddr.sin_port);
	svr->endpoint.flags |= OCF_IPV4 | OCF_TCP;
	if (tcp_socket.tls_v4 == fd) {
		svr->endpoint.flags |= OCF_SECURE;
	}

	svr->sock_fd = sock_fd;
	rt_list_insert(&svr_list, &(svr->node));

	FD_CLR(fd, fds);

	return OCF_CONTINUE;
}

ocf_result_t rt_tcp_receive_message(fd_set *fds, uint8_t *packet, uint16_t *len, ocf_endpoint_s *endpoint)
{

	ocf_result_t ret = OCF_OK;
	RT_LOG_D(TAG, "%s IN", __func__);

	if (tcp_socket.ucast_v4 != INVALID_SOCKET && FD_ISSET(tcp_socket.ucast_v4, fds)) {
		ret = rt_tcp_accept_message(tcp_socket.ucast_v4, fds);
	} else if (tcp_socket.tls_v4 != INVALID_SOCKET && FD_ISSET(tcp_socket.tls_v4, fds)) {
		ret = rt_tcp_accept_message(tcp_socket.tls_v4, fds);
	} else {
		size_t BUFSIZE = 1024;	//TODO
		RT_LOG_D(TAG, "read");

		rt_node_s *itr = svr_list.head;
		while (itr) {
			rt_tcp_svr_s *var = (rt_tcp_svr_s *) rt_list_get_item(&(svr_list), itr);
			if (INVALID_SOCKET != var->sock_fd && FD_ISSET(var->sock_fd, fds)) {
				*len = recv(var->sock_fd, packet, BUFSIZE, 0);
				if (*len > 0) {
					RT_LOG_D(TAG, "recv() : %d bytes", *len);
				} else if (*len == 0) {
					RT_LOG_D(TAG, "session close");
					close(var->sock_fd);
					ret = OCF_CONTINUE;
					var->sock_fd = INVALID_SOCKET;
				} else {
					ret = OCF_COMM_ERROR;
				}
				FD_CLR(var->sock_fd, fds);
				rt_mem_cpy(endpoint, &var->endpoint, sizeof(ocf_endpoint_s));
				break;
			}
			itr = itr->next;
		}
	}

	return ret;
}

void rt_tcp_set_fds(fd_set *sock_set)
{
	if (INVALID_SOCKET != tcp_socket.ucast_v4) {
		FD_SET(tcp_socket.ucast_v4, sock_set);
	}
	if (INVALID_SOCKET != tcp_socket.tls_v4) {
		FD_SET(tcp_socket.tls_v4, sock_set);
	}

	rt_node_s *itr = svr_list.head;
	while (itr) {
		rt_tcp_svr_s *var = (rt_tcp_svr_s *) rt_list_get_item(&(svr_list), itr);

		if (var && INVALID_SOCKET != var->sock_fd) {
			FD_SET(var->sock_fd, sock_set);
		}
		itr = itr->next;
	}
}

ocf_result_t rt_tcp_init(void)
{
	if (OCF_OK != rt_tcp_open_server()) {
		return OCF_ERROR;
	}

	rt_list_init(&svr_list, sizeof(rt_tcp_svr_s), RT_MEMBER_OFFSET(rt_tcp_svr_s, node));

	return OCF_OK;
}

ocf_result_t rt_tcp_terminate(void)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	rt_tcp_close_server();

	rt_list_terminate(&svr_list, NULL);
	RT_LOG_D(TAG, "%s OUT", __func__);

	return OCF_OK;
}

static ocf_result_t rt_tcp_connect(const ocf_endpoint_s *endpoint, rt_tcp_svr_s **svr_item)
{
	int sock_fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (INVALID_SOCKET == sock_fd) {
		RT_LOG_E(TAG, "create socket failed");
		return OCF_COMM_ERROR;
	}

	struct sockaddr_in remote_addr;
	memset(&remote_addr, 0, sizeof(remote_addr));
	remote_addr.sin_family = AF_INET;
	remote_addr.sin_addr.s_addr = endpoint->addr[0];
	remote_addr.sin_port = htons(endpoint->port);

	socklen_t socket_len = sizeof(remote_addr);

	if (connect(sock_fd, (struct sockaddr *)&remote_addr, socket_len) < 0) {
		RT_LOG_E(TAG, "failed to connect socket");
		close(sock_fd);
		return OCF_COMM_ERROR;
	}

	RT_LOG_I(TAG, "connect socket success");

	rt_tcp_svr_s *svr = (rt_tcp_svr_s *) rt_mem_alloc(sizeof(rt_tcp_svr_s));
	if (!svr) {
		RT_LOG_E(TAG, "svr alloc failed");
		close(sock_fd);
		return OCF_MEM_FULL;
	}

	rt_mem_cpy(&svr->endpoint, endpoint, sizeof(ocf_endpoint_s));
	svr->sock_fd = sock_fd;
	rt_list_insert(&svr_list, &(svr->node));

	*svr_item = svr;
	return OCF_OK;
}

ocf_result_t rt_tcp_send_packet(const uint8_t *packet, uint16_t len, int sock_fd, const ocf_endpoint_s *endpoint)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	rt_endpoint_log(OCF_LOG_INFO, TAG, endpoint);

	if (INVALID_SOCKET == sock_fd) {
		RT_LOG_D(TAG, "Invalid socket(%d)", sock_fd);
		return OCF_COMM_ERROR;
	}

	ssize_t remain_len = len;
	do {
		ssize_t send_len = send(sock_fd, packet, remain_len, 0);
		if (INVALID_SOCKET == send_len) {
			RT_LOG_E(TAG, "unicast ipv4tcp send failed");
			return OCF_COMM_ERROR;
		}
		packet += send_len;
		remain_len -= send_len;
	} while (remain_len > 0);

	RT_LOG_I(TAG, "send %i Bytes success!", len);
	RT_LOG_D(TAG, "%s OUT", __func__);

	return OCF_OK;
}

static rt_tcp_svr_s *rt_tcp_get_svr(const ocf_endpoint_s *endpoint)
{
	rt_node_s *itr = svr_list.head;
	while (itr) {
		rt_tcp_svr_s *var = (rt_tcp_svr_s *) rt_list_get_item(&(svr_list), itr);

		if (rt_endpoint_is_equal(endpoint, (const ocf_endpoint_s *)(&(var->endpoint)))) {
			RT_LOG_D(TAG, "The session is found");
			return var;
		}
		itr = itr->next;
	}

	return NULL;
}

ocf_result_t rt_tcp_send_unicast(const uint8_t *packet, uint16_t len, const ocf_endpoint_s *endpoint)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	ocf_result_t res = OCF_ERROR;

	rt_tcp_svr_s *svr_item = rt_tcp_get_svr(endpoint);

	if (!svr_item || INVALID_SOCKET == svr_item->sock_fd) {
		if (OCF_OK != (res = rt_tcp_connect(endpoint, &svr_item))) {
			RT_LOG_E(TAG, "rt_tcp_connect failed");
			return res;
		}
	}

	res = rt_tcp_send_packet(packet, len, svr_item->sock_fd, endpoint);
	RT_LOG_D(TAG, "%s OUT", __func__);

	return res;
}

ocf_result_t rt_tcp_get_secure_port_v4(uint16_t *port)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	if (OCF_OK != rt_tcp_get_assigned_port(tcp_socket.tls_v4, port)) {
		return OCF_ERROR;
	}
	RT_LOG_D(TAG, "TLS_port: %d", *port);
	RT_LOG_D(TAG, "%s OUT", __func__);
	return OCF_OK;
}

ocf_result_t rt_tcp_get_normal_port_v4(uint16_t *port)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	if (OCF_OK != rt_tcp_get_assigned_port(tcp_socket.ucast_v4, port)) {
		return OCF_ERROR;
	}
	RT_LOG_D(TAG, "TCP_port: %d", *port);
	RT_LOG_D(TAG, "%s OUT", __func__);
	return OCF_OK;
}

void rt_tcp_get_secure_sock_v4(int *secure_fd)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	*secure_fd = tcp_socket.tls_v4;
	RT_LOG_D(TAG, "%s OUT", __func__);
}

void rt_tcp_get_normal_sock_v4(int *tcp_v4_normal_fd)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	*tcp_v4_normal_fd = tcp_socket.ucast_v4;
	RT_LOG_D(TAG, "%s OUT", __func__);
}
