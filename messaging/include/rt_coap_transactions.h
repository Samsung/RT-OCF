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
 * - Member variables of struct coap_transaction are modified.
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
 *      CoAP module for reliable transport
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#ifndef COAP_TRANSACTIONS_H_
#define COAP_TRANSACTIONS_H_

#include "rt_coap.h"
#include "rt_list.h"
#include "rt_timer.h"

/*
 * Modulo mask (thus +1) for a random number to get the tick number for the random
 * retransmission time between COAP_RESPONSE_TIMEOUT and COAP_RESPONSE_TIMEOUT*COAP_RESPONSE_RANDOM_FACTOR.
 */
#define COAP_RESPONSE_TIMEOUT_TICKS         (RT_CLOCK_SECOND * COAP_RESPONSE_TIMEOUT)
#define COAP_RESPONSE_TIMEOUT_BACKOFF_MASK  (long)((RT_CLOCK_SECOND * COAP_RESPONSE_TIMEOUT * ((float)COAP_RESPONSE_RANDOM_FACTOR - 1.0)) + 0.5) + 1

typedef enum {
	COAP_TRANSACTION_NEED_SEND,
	COAP_TRANSACTION_SEND_DONE
} coap_transaction_status_t;

typedef enum {
	COAP_TRANSACTION_REQUEST,
	COAP_TRANSACTION_RESPONSE
} coap_transaction_type_t;

/* container for transactions with message buffer and retransmission info */
typedef struct coap_transaction {
	coap_transaction_type_t type;
	coap_transaction_status_t status;
	uint16_t mid;
	rt_timer_s retrans_timer;
	rt_timer_s ttl;
	uint8_t retrans_counter;
	ocf_endpoint_s *endpoint;

	uint16_t packet_len;
	uint8_t packet[COAP_MAX_PACKET_SIZE + 1];	/* +1 for the terminating '\0' which will not be sent
												 * Use snprintf(buf, len+1, "", ...) to completely fill payload */
	rt_node_s node;
} coap_transaction_t;

void rt_coap_register_as_transaction_handler(void);

coap_transaction_t *rt_coap_new_transaction(coap_transaction_type_t type, uint16_t mid, const ocf_endpoint_s *endpoint);
void rt_coap_send_transaction(coap_transaction_t *t);
void rt_coap_clear_transaction(coap_transaction_t *t);
coap_transaction_t *rt_coap_get_request_transaction_by_mid(uint16_t mid);
coap_transaction_t *rt_coap_get_response_transaction_by_mid(uint16_t mid);

void rt_coap_check_transactions(void);

ocf_result_t rt_coap_init_transaction_list(void);
void rt_coap_terminate_transaction_list(void);

bool rt_coap_get_nearest_wakeup_time_of_transactions(rt_clock_time_t *timeout);
#endif							/* COAP_TRANSACTIONS_H_ */
