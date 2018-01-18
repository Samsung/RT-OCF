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

#ifndef MESSAGING_RT_UDP_H_
#define MESSAGING_RT_UDP_H_

#include <stdint.h>
#include <sys/select.h>
#include "ocf_types.h"

#ifdef __cplusplus
extern "C" {
#endif							// __cplusplus

ocf_result_t rt_udp_init(void);
ocf_result_t rt_udp_terminate(void);
void rt_udp_set_fds(fd_set *sock_set);
ocf_result_t rt_udp_send_unicast(const uint8_t *packet, uint16_t len, const ocf_endpoint_s *endpoint);
ocf_result_t rt_udp_send_multicast(const uint8_t *packet, uint16_t len);
ocf_result_t rt_udp_receive_message(fd_set *fds, uint8_t *packet, uint16_t *len, ocf_endpoint_s *endpoint);
ocf_result_t rt_udp_get_secure_port_v4(uint16_t *port);
ocf_result_t rt_udp_get_normal_port_v4(uint16_t *port);

#ifdef __cplusplus
}
#endif							// __cplusplus
#endif							/* MESSAGING_RT_UDP_H_ */
