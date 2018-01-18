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

#ifndef MESSAGING_RT_TRANSPORT_H_
#define MESSAGING_RT_TRANSPORT_H_

#include <stdint.h>
#include "ocf_types.h"
#include "rt_logger.h"

#ifdef __cplusplus
extern "C" {
#endif							// __cplusplus

typedef void (*rt_transport_receive_handler)(uint8_t *packet, uint16_t len, const ocf_endpoint_s *endpoint);

ocf_result_t rt_transport_init(void);
ocf_result_t rt_transport_terminate(void);
ocf_result_t rt_transport_send_packet(const uint8_t *packet, uint16_t len, const ocf_endpoint_s *endpoint);
ocf_result_t rt_transport_set_receive_handler(rt_transport_receive_handler recv_handler);
ocf_result_t rt_transport_unset_receive_handler(void);
ocf_result_t rt_transport_get_local_ipv4(char *buf, size_t len);
ocf_result_t rt_get_ports_v4(uint16_t *udp_normal_port_v4, uint16_t *udp_secure_port_v4, uint16_t *tcp_normal_port_v4, uint16_t *tcp_secure_port_v4);

#ifdef __cplusplus
}
#endif							// __cplusplus
#endif							/* MESSAGING_RT_TRANSPORT_H_ */
