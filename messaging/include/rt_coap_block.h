/*
 * Copyright (c) 2014, Lars Schmertmann <SmallLars@t-online.de>.
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
 *      CoAP module for block 1 handling
 * \author
 *      Lars Schmertmann <SmallLars@t-online.de>
 */

#ifndef COAP_BLOCK_H_
#define COAP_BLOCK_H_

#include "ocf_types.h"
#include "rt_coap.h"
#include "rt_data_handler.h"

bool rt_coap_block_is_block_need(rt_data_s *data, const ocf_endpoint_s *endpoint);
ocf_result_t rt_coap_set_block_response_info(coap_packet_t *packet, rt_data_s *data, const ocf_endpoint_s *endpoint);
ocf_result_t rt_coap_new_block_transaction(const rt_data_s *data, const ocf_endpoint_s *endpoint);
ocf_result_t rt_coap_block_request_handler(coap_packet_t *packet, const ocf_endpoint_s *endpoint, rt_data_s **block_data);
ocf_result_t rt_coap_block_response_handler(coap_packet_t *packet, const ocf_endpoint_s *endpoint);
ocf_result_t rt_coap_block_error_response_handler(coap_packet_t *packet, const ocf_endpoint_s *endpoint);
ocf_result_t rt_coap_init_block(void);
void rt_coap_terminate_block(void);

#endif							/* COAP_BLOCK_H_ */
