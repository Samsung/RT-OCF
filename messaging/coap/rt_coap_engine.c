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
 *      CoAP implementation for the REST Engine.
 * \author
 *      Matthias Kovatsch <kovatsch@inf.ethz.ch>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rt_coap_engine.h"
#include "rt_coap.h"
#include "rt_coap_transactions.h"
#include "rt_data_handler.h"
#include "rt_transport.h"
#include "rt_logger.h"
#include "rt_utils.h"

#define TAG "RT_COAP_ENGINE"

static rt_coap_message_handler g_coap_request_handler = NULL;
static rt_coap_message_handler g_coap_response_handler = NULL;

ocf_result_t rt_coap_set_request_message_handler(rt_coap_message_handler request_handler)
{
	RT_VERIFY_NON_NULL(request_handler, TAG, "request_handler");

	g_coap_request_handler = request_handler;
	return OCF_OK;
}

ocf_result_t rt_coap_unset_request_message_handler(void)
{
	RT_VERIFY_NON_NULL_RET(g_coap_request_handler, TAG, "g_coap_request_handler is NULL", OCF_ERROR);

	g_coap_request_handler = NULL;
	return OCF_OK;
}

ocf_result_t rt_coap_set_response_message_handler(rt_coap_message_handler response_handler)
{
	RT_VERIFY_NON_NULL(response_handler, TAG, "response_handler");

	g_coap_response_handler = response_handler;
	return OCF_OK;
}

ocf_result_t rt_coap_unset_response_message_handler(void)
{
	RT_VERIFY_NON_NULL_RET(g_coap_response_handler, TAG, "g_coap_request_handler is NULL", OCF_ERROR);

	g_coap_response_handler = NULL;
	return OCF_OK;
}

void rt_coap_receive(uint8_t *packet, uint16_t len, const ocf_endpoint_s *endpoint)
{
	RT_VERIFY_NON_NULL_VOID(packet, TAG, "packet");
	RT_VERIFY_NON_NULL_VOID(endpoint, TAG, "endpoint");
	RT_VERIFY_NON_NULL_VOID(g_coap_request_handler, TAG, "g_coap_request_handler");
	RT_VERIFY_NON_NULL_VOID(g_coap_response_handler, TAG, "g_coap_response_handler");
	coap_status_t status_code = NO_ERROR;

	/* static declaration reduces stack peaks and program code size */
	static coap_packet_t message[1];	/* this way the packet can be treated as pointer as usual */
	static coap_transaction_t *transaction = NULL;

	status_code = rt_coap_parse_message(message, packet, len);

	ocf_result_t ret = OCF_OK;
	if (status_code == NO_ERROR) {
		/*TODO duplicates suppression, if required by application */
		RT_LOG_D(TAG, " --------------------------------------------------- ");
		RT_LOG_D(TAG, "  Version %u, Code %u, mid %u", message->version, message->code, message->mid);
		RT_LOG_D(TAG, "  Token Len: %u, Token: 0x%02x", message->token.len, message->token.token[0]);
		RT_LOG_D(TAG, "  Message type: %d (0:CON 1:NON 2:ACK 3:RST)", message->type);
		RT_LOG_D(TAG, "  URI: %.*s", (int)message->uri_path_len, message->uri_path);
		RT_LOG_D(TAG, "  Payload: len : %d", message->payload_len);
		if (IS_OPTION(message, COAP_OPTION_BLOCK1)) {
			RT_LOG_D(TAG, "  block1 option ON");
		}
		if (IS_OPTION(message, COAP_OPTION_BLOCK2)) {
			RT_LOG_D(TAG, "  block2 option ON");
		}
		if (IS_OCF_OPTION(message, COAP_OPTION_OCF_ACCEPT)) {
			RT_LOG_D(TAG, "  OCF accept version : %u", message->ocf_accept);
		}
		if (IS_OCF_OPTION(message, COAP_OPTION_OCF_CONTENT_FORMAT)) {
			RT_LOG_D(TAG, "  OCF content format version : %u", message->ocf_content_format);
		}
		RT_LOG_D(TAG, " --------------------------------------------------- ");

		/* handle requests */
		if (message->code >= COAP_GET && message->code <= COAP_DELETE) {
			rt_data_s *receive_data = NULL;
			if (IS_OPTION(message, COAP_OPTION_BLOCK1)) {
				ret = rt_coap_block_request_handler(message, endpoint, &receive_data);
			} else if (IS_OPTION(message, COAP_OPTION_BLOCK2)) {
				ret = rt_coap_block_response_handler(message, endpoint);
			} else {
				receive_data = rt_receive_data_make_item(message);
				RT_VERIFY_NON_NULL_VOID(receive_data, TAG, "receive_data");
			}

			if (receive_data) {
				if (g_coap_request_handler) {
					ret = g_coap_request_handler(receive_data, endpoint);
					if (OCF_OK != ret) {
						RT_LOG_E(TAG, "g_coap_request_handler failed!");
						rt_data_free_item(receive_data);
					}
				} else {
					RT_LOG_E(TAG, "g_coap_request_handler is not set yet!");
					//TODO: Error handling
				}
			}
			/* handle responses */
		} else {
			if (message->type == COAP_TYPE_CON && message->code == 0) {
				RT_LOG_D(TAG, "Received Ping");
				status_code = PING_RESPONSE;
				rt_coap_init_message(message, COAP_TYPE_RST, PING_RESPONSE, message->mid);
				uint8_t ping_response[COAP_MAX_PACKET_SIZE + 1];
				uint16_t ping_response_len = rt_coap_serialize_message(message, ping_response);
				rt_coap_send_message(ping_response, ping_response_len, endpoint);
			} else if (COAP_TYPE_ACK == message->type && NO_ERROR == message->code) {
				RT_LOG_D(TAG, "Received ACK");
				transaction = rt_coap_get_request_transaction_by_mid(message->mid);
				RT_VERIFY_NON_NULL_VOID(transaction, TAG, "transaction by mid");
				transaction->status = COAP_TRANSACTION_SEND_DONE;
				return;

			} else if (message->type == COAP_TYPE_ACK || message->type == COAP_TYPE_NON) {
				RT_LOG_D(TAG, "Received Response");
				rt_data_s *receive_data = NULL;

				if (IS_OPTION(message, COAP_OPTION_BLOCK1)) {
					if (CREATED_2_01 <= message->code && message->code <= CONTINUE_2_31) {
						ret = rt_coap_block_response_handler(message, endpoint);
					} else {
						ret = rt_coap_block_error_response_handler(message, endpoint);
					}
				}

				if (IS_OPTION(message, COAP_OPTION_BLOCK2)) {
					if (CREATED_2_01 <= message->code && message->code <= CONTINUE_2_31) {
						ret = rt_coap_block_request_handler(message, endpoint, &receive_data);
					} else {
						ret = rt_coap_block_error_response_handler(message, endpoint);
					}
				}

				if (!IS_OPTION(message, COAP_OPTION_BLOCK1) && !IS_OPTION(message, COAP_OPTION_BLOCK2)) {
					receive_data = rt_receive_data_make_item(message);
					RT_VERIFY_NON_NULL_VOID(receive_data, TAG, "receive_data");
				}

				if (receive_data) {
					if (g_coap_response_handler) {
						ret = g_coap_response_handler(receive_data, endpoint);
						if (OCF_OK != ret) {
							RT_LOG_E(TAG, "g_coap_response_handler failed!");
							rt_data_free_item(receive_data);
						}
					} else {
						RT_LOG_E(TAG, "g_coap_response_handler is not set yet!");
						//TODO: Error handling
					}
				}
			} else if (message->type == COAP_TYPE_RST) {
				RT_LOG_D(TAG, "Received RST");
				/* cancel possible subscriptions */
				// rt_coap_remove_observer_by_mid(&UIP_IP_BUF->srcipaddr, UIP_UDP_BUF->srcport, message->mid);
			}

			while ((transaction = rt_coap_get_request_transaction_by_mid(message->mid))) {
				if (!transaction->endpoint) {	//TODO : Should delete this transaction after ttl.
					RT_LOG_D(TAG, "Multicast packet don't remove.");
					break;
				}

				RT_LOG_D(TAG, "Clear transaction MID:%d", message->mid);
				rt_coap_clear_transaction(transaction);
				transaction = NULL;
			}

			//TODO : check for response CON packets.

// #if COAP_OBSERVE_CLIENT
//          /* if observe notification */
//          if ((message->type == COAP_TYPE_CON || message->type == COAP_TYPE_NON)
//              && IS_OPTION(message, COAP_OPTION_OBSERVE)) {
//              PRINTF("Observe [%u]\n", message->observe);
//              rt_coap_handle_notification(&UIP_IP_BUF->srcipaddr, UIP_UDP_BUF->srcport, message);
//          }
// #endif                           /* COAP_OBSERVE_CLIENT */
		}						/* request or response */
	}

	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "%s error code : %d", __func__, ret);
		//TODO: Error handling
	}
}
