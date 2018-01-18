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

#include <net/if.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "rt_transport.h"
#include "rt_mem.h"
#include "rt_udp.h"
#include "rt_thread.h"
#include "rt_message_queue.h"
#include "rt_coap.h"
#include "rt_utils.h"
#include "rt_string.h"

#define INVALID_SOCKET (-1)

#define SELECT_TIME_SEC 1

#define IPV4_LENGTH 4
#define IPV6_LENGTH 16

#ifndef FD_SETSIZE
#define FD_SETSIZE (CONFIG_NFILE_DESCRIPTORS + CONFIG_NSOCKET_DESCRIPTORS)
#endif

static const char *TAG = "RT_TRANSPORT";

static rt_thread_s receive_thread;

static int receive_thread_terminate = 0;

static rt_transport_receive_handler g_recv_handler = NULL;

static rt_message_queue_s send_queue;

typedef struct {
	const uint8_t *packet;
	uint16_t len;
	const ocf_endpoint_s *endpoint;
} rt_send_queue_item_s;

static void rt_transport_recv_callback(uint8_t *packet, uint16_t len, ocf_endpoint_s *endpoint)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	if (g_recv_handler) {
		RT_LOG_D(TAG, "rt_transport_recv_callback");
		g_recv_handler(packet, len, endpoint);
	}

	RT_LOG_D(TAG, "%s OUT", __func__);
	return;
}

static void *rt_transport_receive_runner(void *data)
{
	struct timeval timeout;
	int counts = 0;
	uint8_t packet[COAP_MAX_PACKET_SIZE];
	uint16_t len = 0;
	fd_set read_sock_set;

	RT_LOG_D(TAG, "%s IN", __func__);
	while (!receive_thread_terminate) {
		timeout.tv_sec = SELECT_TIME_SEC;	//TODO : cause letency when ocf_terminate. (need to use pipe for direct quit.)
		timeout.tv_usec = 0;

		FD_ZERO(&read_sock_set);
		rt_udp_set_fds(&read_sock_set);
		rt_tcp_set_fds(&read_sock_set);

		counts = select(FD_SETSIZE, &read_sock_set, NULL, NULL, &timeout);

		while (0 < counts--) {
			//TODO : Improve multiple endpoint handler
			ocf_endpoint_s endpoint;
			endpoint.flags = OCF_DEFAULT_FLAGS;

			ocf_result_t ret = rt_udp_receive_message(&read_sock_set, packet, &len, &endpoint);
			if (OCF_OK == ret) {	// udp recv
				goto upper;
			} else if (OCF_CONTINUE == ret) {
				ret = rt_tcp_receive_message(&read_sock_set, packet, &len, &endpoint);
				if (OCF_OK == ret) {	// tcp recv
					goto upper;
				} else if (OCF_CONTINUE == ret) {	// tcp accept
					continue;
				}
			}
			//TODO error handler
			continue;

upper:
			RT_LOG_D(TAG, "%i Bytes data received.", len);
			rt_endpoint_log(OCF_LOG_INFO, TAG, &endpoint);
			RT_LOG_BUFFER_D(TAG, packet, len);

			if (endpoint.flags & OCF_SECURE) {
				RT_LOG_D(TAG, "Encrypted data received.");
				if (rt_ssl_decrypt(packet, len, &endpoint) != OCF_OK) {
					//TODO : Error handler
					RT_LOG_E(TAG, "rt_ssl_decrypt failed !!");
				}
			} else {
				RT_LOG_D(TAG, "UPPER HANDLER");
				rt_transport_recv_callback(packet, len, &endpoint);
			}
		}
	}
	RT_LOG_D(TAG, "%s OUT", __func__);

	return NULL;
}

static void rt_transport_send_queue_runner(void *data)
{
	ocf_result_t res = OCF_OK;
	rt_send_queue_item_s *item = (rt_send_queue_item_s *) data;
	RT_LOG_D(TAG, "%s IN", __func__);

	if (item->endpoint) {
		if (item->endpoint->flags & OCF_UDP) {
			res = rt_udp_send_unicast(item->packet, item->len, item->endpoint);
		} else if (item->endpoint->flags & OCF_TCP) {
			res = rt_tcp_send_unicast(item->packet, item->len, item->endpoint);
		}
	} else {
		res = rt_udp_send_multicast(item->packet, item->len);
	}

	if (OCF_OK != res) {
		//TODO erroe handler
		rt_endpoint_log(OCF_LOG_ERROR, TAG, item->endpoint);
		RT_LOG_E(TAG, "=>send error!");
	}
}

static void rt_transport_send_queue_item_free_func(void *data)
{
	rt_send_queue_item_s *item = (rt_send_queue_item_s *) data;

	if (item->packet) {
		rt_mem_free((uint8_t *) item->packet);
	}

	if (item->endpoint) {
		rt_mem_free((ocf_endpoint_s *) item->endpoint);
	}
}

static ocf_result_t rt_transport_send_queue_enqueue(const uint8_t *packet, uint16_t len, const ocf_endpoint_s *endpoint)
{
	RT_VERIFY_NON_NULL_RET(packet, TAG, "packet is null", OCF_INVALID_PARAM);

	rt_send_queue_item_s *item = (rt_send_queue_item_s *) rt_mem_alloc(sizeof(rt_send_queue_item_s));
	RT_VERIFY_NON_NULL_RET(item, TAG, "item", OCF_MEM_FULL);

	item->packet = rt_mem_dup(packet, len);
	if (!item->packet) {
		RT_LOG_E(TAG, "can't memory duplicate packet");
		return OCF_MEM_FULL;
	}

	item->len = len;
	item->endpoint = NULL;
	if (endpoint) {
		item->endpoint = rt_mem_dup(endpoint, sizeof(ocf_endpoint_s));
		if (!item->endpoint) {
			RT_LOG_E(TAG, "can't memory duplicate endpoint");
			return OCF_MEM_FULL;
		}
	}

	ocf_result_t ret = rt_message_queue_enqueue(&send_queue, (void *)item);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_transport_send_queue_enqueue failed!");
		rt_transport_send_queue_item_free_func(item);
		rt_mem_free(item);
		item = NULL;
		return ret;
	}

	return OCF_OK;
}

ocf_result_t rt_transport_init(void)
{
	ocf_result_t ret = OCF_OK;

	if (OCF_OK != (ret = rt_udp_init())) {
		RT_LOG_E(TAG, "rt_udp_init failed!");
		rt_transport_terminate();
		return ret;
	}

	if (OCF_OK != (ret = rt_tcp_init())) {
		RT_LOG_E(TAG, "rt_tcp_init failed!");
		rt_transport_terminate();
		return ret;
	}

	if (receive_thread.thread) {
		RT_LOG_E(TAG, "receive_thread is already created!");
		rt_transport_terminate();
		return OCF_ERROR;
	}

	if (OCF_OK != (ret = rt_message_queue_init(&send_queue, rt_transport_send_queue_runner, rt_transport_send_queue_item_free_func, "send_queue"))) {
		RT_LOG_E(TAG, "fail to init Send Queue");
		rt_transport_terminate();
		return ret;
	}

	rt_ssl_set_callback(rt_transport_recv_callback, rt_transport_send_queue_enqueue);

	receive_thread_terminate = 0;

	if (OCF_OK != (ret = rt_thread_init(&receive_thread, rt_transport_receive_runner, "receive_thread", 0, NULL))) {
		RT_LOG_E(TAG, "fail to create receive thread");
		rt_transport_terminate();
		return ret;
	}

	return OCF_OK;
}

ocf_result_t rt_transport_set_receive_handler(rt_transport_receive_handler recv_handler)
{
	if (!recv_handler) {
		RT_LOG_E(TAG, "recv_handler is NULL");
		return OCF_ERROR;
	}

	g_recv_handler = recv_handler;
	return OCF_OK;
}

ocf_result_t rt_transport_unset_receive_handler(void)
{
	if (!g_recv_handler) {
		RT_LOG_E(TAG, "g_recv_handler is NULL");
		return OCF_ERROR;
	}

	g_recv_handler = NULL;
	return OCF_OK;
}

static void rt_transport_receive_thread_terminate_func(void *user_data)
{
	__sync_bool_compare_and_swap(&receive_thread_terminate, 0, 1);
}

ocf_result_t rt_transport_terminate(void)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	rt_transport_unset_receive_handler();

	if (!receive_thread_terminate && receive_thread.thread) {
		rt_thread_terminate(&receive_thread, rt_transport_receive_thread_terminate_func, NULL);
	}
	rt_message_queue_terminate(&send_queue);

	rt_udp_terminate();

	rt_tcp_terminate();

	RT_LOG_D(TAG, "%s OUT", __func__);

	return OCF_OK;
}

ocf_result_t rt_transport_send_packet(const uint8_t *packet, uint16_t len, const ocf_endpoint_s *endpoint)
{
	ocf_result_t res = OCF_ERROR;

	if (endpoint && endpoint->flags & OCF_SECURE) {
		if (OCF_OK != (res = rt_ssl_encrypt(packet, len, endpoint))) {
			RT_LOG_E(TAG, "Encrypt failed !!");
		}
	} else {
		if (OCF_OK != (res = rt_transport_send_queue_enqueue(packet, len, endpoint))) {
			RT_LOG_E(TAG, "Enqueue failed !!");
		}
	}

	return res;
}

ocf_result_t rt_get_ports_v4(uint16_t *udp_normal_port_v4, uint16_t *udp_secure_port_v4, uint16_t *tcp_normal_port_v4, uint16_t *tcp_secure_port_v4)
{
	RT_LOG_D(TAG, "%s IN", __func__);

	ocf_result_t res = OCF_OK;

	if (NULL != udp_normal_port_v4) {
		res = rt_udp_get_normal_port_v4(udp_normal_port_v4);
		if (OCF_OK != res) {
			RT_LOG_D(TAG, "%s OUT", __func__);
			return res;
		}
	}

	if (NULL != udp_secure_port_v4) {
		res = rt_udp_get_secure_port_v4(udp_secure_port_v4);
		if (OCF_OK != res) {
			RT_LOG_D(TAG, "%s OUT", __func__);
			return res;
		}
	}

	if (NULL != tcp_normal_port_v4) {
		res = rt_tcp_get_secure_port_v4(tcp_normal_port_v4);
		if (OCF_OK != res) {
			RT_LOG_D(TAG, "%s OUT", __func__);
			return res;
		}
	}

	if (NULL != tcp_secure_port_v4) {
		res = rt_tcp_get_normal_port_v4(tcp_secure_port_v4);
		if (OCF_OK != res) {
			RT_LOG_D(TAG, "%s OUT", __func__);
			return res;
		}
	}

	RT_LOG_D(TAG, "%s OUT", __func__);
	return res;
}

ocf_result_t rt_transport_get_local_ipv4(char *buf, size_t len)
{
	int sock_fd = 0;
	struct ifreq *ifr;
	struct sockaddr_in *sin;
	struct ifconf ifcfg;
	int i;
	int numreqs = 3;
	int num_nic = 0;
	sock_fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (INVALID_SOCKET == sock_fd) {
		RT_LOG_E(TAG, "ipv4 socket create failed!");
		return OCF_ERROR;
	}
	memset(&ifcfg, 0, sizeof(ifcfg));
	ifcfg.ifc_buf = NULL;
	ifcfg.ifc_len = sizeof(struct ifreq) * numreqs;
	ifcfg.ifc_buf = (char *)rt_mem_alloc(ifcfg.ifc_len);
	if (!ifcfg.ifc_buf) {
		RT_LOG_E(TAG, "ifc_buf alloc failed!");
		close(sock_fd);
		return OCF_MEM_FULL;
	}

	if (0 > ioctl(sock_fd, SIOCGIFCONF, (void *)&ifcfg)) {
		RT_LOG_E(TAG, "ioctl failed!");
		rt_mem_free(ifcfg.ifc_buf);
		close(sock_fd);

		return OCF_ERROR;
	}

	num_nic = ifcfg.ifc_len / sizeof(struct ifreq);
	for (i = 0, ifr = ifcfg.ifc_req; i < num_nic; ifr++, i++) {
		RT_LOG_D(TAG, "Network interface name : %s", ifr->ifr_name);
		sin = (struct sockaddr_in *)&ifr->ifr_addr;
		if ((sin->sin_addr.s_addr) == htonl(INADDR_LOOPBACK)) {
			RT_LOG_D(TAG, "Loop Back");
			continue;
		} else {
			rt_strncpy(buf, inet_ntoa(sin->sin_addr), len);
			RT_LOG_D(TAG, "Local IP: %s", buf);
			break;
		}
	}
	rt_mem_free(ifcfg.ifc_buf);
	close(sock_fd);

	return OCF_OK;
}
