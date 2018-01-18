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

/*
 * Summary of modifications from original source code
 * - struct coap_observable is renamed.
 * - struct coap_observer is renamed.
 * - coap_add_observer() is deleted.
 * - All functions are renamed.
 */

/*
 * Copyright (c) 2013, Institute for Pervasive Computing, ETH Zurich
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the Institute nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE INSTITUTE AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE INSTITUTE OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file is part of the Contiki operating system.
 */

/**
 * \file
 *      CoAP module for observing resources (draft-ietf-core-observe-11).
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#ifndef COAP_OBSERVE_H_
#define COAP_OBSERVE_H_

#include "rt_coap.h"
#include "rt_coap_transactions.h"
#include "stimer.h"

#define rt_coap_observer_URL_LEN 20

typedef struct rt_coap_observable {
	uint32_t observe_clock;
	struct stimer orphan_timer;
	list_t observers;
	coap_packet_t notification;
	uint8_t buffer[COAP_MAX_PACKET_SIZE + 1];
} rt_coap_observable_t;

typedef struct rt_coap_observer {
	struct rt_coap_observer *next;	/* for LIST */

	char url[rt_coap_observer_URL_LEN];
	uint8_t addr[4];
	uint16_t port;
	uint8_t token_len;
	uint8_t token[COAP_TOKEN_LEN];
	uint16_t last_mid;

	int32_t obs_counter;
//TODO : need to define etimer
//  struct etimer retrans_timer;
	uint8_t retrans_counter;
} rt_coap_observer_t;

list_t rt_coap_get_observers(void);
void rt_coap_remove_observer(rt_coap_observer_t *o);
int rt_coap_remove_observer_by_client(uint8_t *addr, uint16_t port);
int rt_coap_remove_observer_by_token(uint8_t *addr, uint16_t port, uint8_t *token, size_t token_len);
int rt_coap_remove_observer_by_uri(uint8_t *addr, uint16_t port, const char *uri);
int rt_coap_remove_observer_by_mid(uint8_t *addr, uint16_t port, uint16_t mid);

void rt_coap_notify_observers(resource_t *resource);
void rt_coap_notify_observers_sub(resource_t *resource, const char *subpath);

void rt_coap_observe_handler(resource_t *resource, void *request, void *response);

#endif							/* COAP_OBSERVE_H_ */
