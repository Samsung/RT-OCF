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

#ifndef MESSAGING_RT_SSL_H_
#define MESSAGING_RT_SSL_H_

#include <stdint.h>
#include "ocf_types.h"
#include "rt_transport.h"
#include "rt_timer.h"

#ifdef __cplusplus
extern "C" {
#endif							// __cplusplus

typedef enum {
	RT_SSL_HANDSHAKE_NON = 0,
	RT_SSL_HANDSHAKE_ONGOING,
	RT_SSL_HANDSHAKE_OVER,
	RT_SSL_HANDSHAKE_FAILURE
} rt_ssl_state_t;

typedef void (*ssl_send_callback)(const uint8_t *packet, uint16_t len, const ocf_endpoint_s *endpoint);
typedef void (*ssl_recv_callback)(uint8_t *packet, uint16_t len, const ocf_endpoint_s *endpoint);
typedef void (*ssl_handshake_callback)(const ocf_endpoint_s *endpoint);
typedef ocf_result_t(*rt_ssl_get_psk_handler)(const uint8_t *uuid, size_t uuid_len, uint8_t *psk, size_t *psk_len);

ocf_result_t rt_ssl_init(void);
ocf_result_t rt_ssl_terminate(void);
ocf_result_t rt_ssl_encrypt(const uint8_t *packet, uint16_t len, const ocf_endpoint_s *endpoint);
ocf_result_t rt_ssl_decrypt(uint8_t *packet, uint16_t len, ocf_endpoint_s *endpoint);
ocf_result_t rt_ssl_close_connection(ocf_endpoint_s *endpoint);
ocf_result_t rt_ssl_check_session(ocf_endpoint_s *endpoint, rt_ssl_state_t *ssl_state);
ocf_result_t rt_ssl_initialize_handshake(const ocf_endpoint_s *endpoint);
void rt_ssl_set_callback(ssl_recv_callback recv_callback, ssl_send_callback send_callback);
void rt_ssl_check_handshake_timeout(void);
bool rt_ssl_get_nearest_wakeup_time_of_peers(rt_clock_time_t *wakeup_time);
void rt_ssl_set_handshake_callback(ssl_handshake_callback hanshake_callback);

#ifdef __cplusplus
}
#endif							// __cplusplus
#endif							/* MESSAGING_RT_SSL_H_ */
