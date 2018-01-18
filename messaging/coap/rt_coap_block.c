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


#include <stdio.h>
#include <string.h>

#include "rt_coap_block.h"
#include "rt_coap_transactions.h"
#include "rt_logger.h"
#include "rt_utils.h"
#include "rt_mem.h"
#include "rt_endpoint.h"
#include "rt_list.h"
#include "rt_timer.h"

#define TAG "RT_COAP_BLK"

#define BLOCK_SIZE (1024)
#define MAX_BLOCK_COUNT (0x0FFFFF)

typedef struct {
	ocf_endpoint_s endpoint;
	rt_data_s data;
	uint32_t offset;
	uint32_t num;
	size_t block_size;
	rt_timer_s ttl;
	rt_node_s node;
} rt_coap_send_block_s;

typedef struct {
	ocf_endpoint_s endpoint;
	uint16_t mid;
	rt_token_s token;
	const char *uri_path;
	uint8_t *packet;
	uint32_t packet_len;
	uint32_t offset;
	uint32_t num;
	size_t block_size;
	rt_timer_s ttl;
	rt_node_s node;
} rt_coap_receive_block_s;

typedef struct {
	ocf_endpoint_s endpoint;
	rt_token_s token;
	uint32_t num;
	size_t block_size;
	rt_timer_s ttl;
	rt_node_s node;
} rt_block_response_info_s;

//Sended blockwise transfer packet list
static rt_list_s* rt_coap_block_send_list = NULL;

//Received blockwise transfer packet list
static rt_list_s* rt_coap_block_receive_list = NULL;

//Received blockwise transfer packet's response info list
static rt_list_s* rt_block_response_info_list = NULL;
/*----------------------------------------------------------------------------*/

bool rt_coap_block_is_block_need(rt_data_s *data, const ocf_endpoint_s *endpoint)
{
	RT_VERIFY_NON_NULL_RET(data, TAG, NULL, false);
	RT_VERIFY_NON_NULL_RET(data->payload, TAG, NULL, false);
	RT_VERIFY_NON_NULL_RET(endpoint, TAG, NULL, false);

	if (endpoint->flags & OCF_TCP) {
		return false;
	}
	
	return (data->payload_len > BLOCK_SIZE) ? true : false;
}

ocf_result_t rt_coap_set_block_response_info(coap_packet_t *packet, rt_data_s *data, const ocf_endpoint_s *endpoint)
{
	RT_VERIFY_NON_NULL_RET(rt_block_response_info_list, TAG, "rt_block_response_info_list", OCF_ERROR);
	RT_VERIFY_NON_NULL(packet, TAG, "packet");
	RT_VERIFY_NON_NULL(data, TAG, "data");
	RT_VERIFY_NON_NULL(data->token.token, TAG, "data->token.token");
	RT_VERIFY_NON_NULL(endpoint, TAG, "endpoint");

	rt_node_s *itr = rt_block_response_info_list->head;
	rt_block_response_info_s *target_info = NULL;

	while (itr) {
		rt_block_response_info_s *var = (rt_block_response_info_s *) rt_list_get_item(rt_block_response_info_list, itr);
		if (rt_coap_compare_token(&data->token, &var->token) && rt_endpoint_is_equal(endpoint, &var->endpoint)) {
			target_info = var;

			if (0 == rt_coap_set_header_block1(packet, target_info->num, 0, target_info->block_size)) {
				RT_LOG_E(TAG, "rt_coap_set_header_block1 failed!");
				return OCF_ERROR;
			}

			rt_block_response_info_s *info = (rt_block_response_info_s *) rt_list_delete_by_node(rt_block_response_info_list, &target_info->node);
			if (info) {
				rt_mem_free(info);
				info = NULL;
			}
			return OCF_OK;
		} else if (var->ttl.interval != 0 && rt_timer_expired(&var->ttl)) {
			RT_LOG_D(TAG, "Receive block packet's[0x%x] response info ttl is expired!", var->token.token[0]);
			rt_block_response_info_s *info = (rt_block_response_info_s *) rt_list_delete_by_node(rt_block_response_info_list, &var->node);
			if (info) {
				rt_mem_free(info);
				info = NULL;
			}
		}
		itr = itr->next;
	}

	RT_LOG_E(TAG, "Can't find block response for token[0x%x]", data->token.token[0]);
	return OCF_ERROR;
}

static void send_block_item_release(void *item)
{
	rt_coap_send_block_s *block_item = (rt_coap_send_block_s *) item;
	RT_VERIFY_NON_NULL_VOID(block_item, TAG, "block_item is NULL");

	if (block_item->data.uri_path) {
		rt_mem_free((char *)block_item->data.uri_path);
		block_item->data.uri_path = NULL;
	}
	if (block_item->data.query) {
		rt_mem_free((char *)block_item->data.query);
		block_item->data.query = NULL;
	}
	if (block_item->data.payload) {
		rt_mem_free(block_item->data.payload);
		block_item->data.payload = NULL;
	}
}

static void receive_block_item_release(void *item)
{
	RT_VERIFY_NON_NULL_VOID(item, TAG, "receive_block is NULL");
	rt_coap_receive_block_s *receive_block = (rt_coap_receive_block_s *) item;

	if (receive_block->uri_path) {
		rt_mem_free((char *)receive_block->uri_path);
		receive_block->uri_path = NULL;
	}
	if (receive_block->packet) {
		rt_mem_free(receive_block->packet);
		receive_block->packet = NULL;
	}
}

static bool rt_coap_block_find_block_item(rt_list_s *list, coap_option_t block_opt, const rt_token_s token, const ocf_endpoint_s *endpoint, void **exist_packet)
{
	RT_VERIFY_NON_NULL_RET(list, TAG, "list", false);
	RT_VERIFY_NON_NULL_RET(token.token, TAG, "token.token", false);
	RT_VERIFY_NON_NULL_RET(endpoint, TAG, "endpoint", false);

	rt_node_s *itr = list->head;
	*exist_packet = NULL;
	rt_data_flag_t trans_type = (block_opt == COAP_OPTION_BLOCK1) ? RT_OPTION_TRANSACTION_REQUEST : RT_OPTION_TRANSACTION_RESPONSE;
	while (itr) {
		if (list == rt_coap_block_send_list) {
			rt_coap_send_block_s *var = (rt_coap_send_block_s *) rt_list_get_item(list, itr);
			if (trans_type & var->data.flags && rt_coap_compare_token(&token, &var->data.token) && rt_endpoint_is_equal(endpoint, &var->endpoint)) {
				RT_LOG_D(TAG, "found exist block packet.");
				*exist_packet = var;
				return true;
			}
		} else if (list == rt_coap_block_receive_list) {
			rt_coap_receive_block_s *var = (rt_coap_receive_block_s *) rt_list_get_item(list, itr);
			if (rt_coap_compare_token(&token, &var->token) && rt_endpoint_is_equal(endpoint, &var->endpoint)) {
				RT_LOG_D(TAG, "found exist block packet.");
				*exist_packet = var;
				return true;
			} else if (var->ttl.interval != 0 && rt_timer_expired(&var->ttl)) {
				RT_LOG_D(TAG, "Receive block packet's[0x%x] ttl is expired!", var->token.token[0]);
				rt_coap_receive_block_s *info = (rt_coap_receive_block_s *) rt_list_delete_by_node(list, &var->node);
				if (info) {
					receive_block_item_release(info);
					rt_mem_free(info);
					info = NULL;
				}
			}
		}
		itr = itr->next;
	}

	RT_LOG_D(TAG, "Can't find exist block packet.");
	return false;
}

static void rt_remove_receive_block_node(rt_node_s *node)
{
	RT_VERIFY_NON_NULL_VOID(rt_coap_block_receive_list, TAG, "rt_coap_block_receive_list");
	rt_coap_receive_block_s *var = (rt_coap_receive_block_s *) rt_list_delete_by_node(rt_coap_block_receive_list, node);
	if (var) {
		receive_block_item_release(var);
		rt_mem_free(var);
		var = NULL;
	}
}

static void rt_remove_send_block_node(rt_node_s *node)
{
	RT_VERIFY_NON_NULL_VOID(rt_coap_block_send_list, TAG, "rt_coap_block_send_list");
	rt_coap_send_block_s *var = (rt_coap_send_block_s *) rt_list_delete_by_node(rt_coap_block_send_list, node);
	if (var) {
		send_block_item_release(var);
		rt_mem_free(var);
		var = NULL;
	}
}

static void rt_send_error_response(coap_packet_t *packet, const ocf_endpoint_s *endpoint, coap_status_t err)
{
	RT_VERIFY_NON_NULL_VOID(packet, TAG, "packet");
	RT_VERIFY_NON_NULL_VOID(endpoint, TAG, "endpoint");

	coap_packet_t err_response[1];

	
	coap_message_type_t type = (packet->type == COAP_TYPE_CON || packet->type == COAP_TYPE_ACK) ? COAP_TYPE_ACK : COAP_TYPE_NON;
	rt_coap_init_message(err_response, type, err, packet->mid);	
	rt_coap_copy_token(&err_response->token, &packet->token);

	RT_LOG_E(TAG, "[C<-S]Send err response[%d]", err);
	if (IS_OPTION(packet, COAP_OPTION_BLOCK1) && !IS_OPTION(packet, COAP_OPTION_BLOCK2)) {
		if (0 == rt_coap_set_header_block1(err_response, 0, 0, BLOCK_SIZE)) {
			RT_LOG_E(TAG, "rt_coap_set_header_block1 failed!");
			return;
		}
	} else if (IS_OPTION(packet, COAP_OPTION_BLOCK2)) {
		if (0 == rt_coap_set_header_block2(err_response, 0, 0, BLOCK_SIZE)) {
			RT_LOG_E(TAG, "rt_coap_set_header_block2 failed!");
			return;
		}
	} else {
		RT_LOG_E(TAG, "Invaild coap packet!");
		return;
	}

	if (REQUEST_ENTITY_TOO_LARGE_4_13 == err) {
		rt_coap_set_header_size1(err_response, BLOCK_SIZE);
	}
	
	uint8_t payload[COAP_MAX_PACKET_SIZE + 1];
	uint16_t payload_len;
	if (0 == (payload_len = rt_coap_serialize_message(err_response, payload))) {
		RT_LOG_E(TAG, "rt_coap_serialize_message failed!");
		return;
	}
	
	rt_coap_send_message(payload, payload_len, endpoint);
}

static ocf_result_t rt_coap_block_remove_send_block(rt_data_flag_t type, const rt_token_s token, const ocf_endpoint_s *endpoint)
{
	RT_VERIFY_NON_NULL_RET(rt_coap_block_send_list, TAG, "rt_coap_block_send_list", OCF_ERROR);
	RT_VERIFY_NON_NULL(token.token, TAG, "token.token");
	RT_VERIFY_NON_NULL(endpoint, TAG, "endpoint");

	RT_LOG_D(TAG, "Remove send block regarding token:0x%x", token.token[0]);

	rt_node_s *itr = rt_coap_block_send_list->head;
	rt_coap_send_block_s *target_send_block = NULL;

	while (itr) {
		rt_coap_send_block_s *var = (rt_coap_send_block_s *) rt_list_get_item(rt_coap_block_send_list, itr);
		if ((type & var->data.flags) && rt_coap_compare_token(&token, &var->data.token) && rt_endpoint_is_equal(endpoint, &var->endpoint)) {
			target_send_block = var;

			rt_coap_send_block_s *info = (rt_coap_send_block_s *) rt_list_delete_by_node(rt_coap_block_send_list, &target_send_block->node);
			if (info) {
				send_block_item_release(info);
				rt_mem_free(info);
				info = NULL;
			}

			RT_LOG_D(TAG, "found exist send block packet and removed success!");
			return OCF_OK;
		}
		itr = itr->next;
	}

	RT_LOG_E(TAG, "Can't find exist send block packet.");
	return OCF_ERROR;
}

ocf_result_t rt_coap_block_request_handler(coap_packet_t *packet, const ocf_endpoint_s *endpoint, rt_data_s **block_data)
{
	RT_VERIFY_NON_NULL_RET(rt_coap_block_receive_list, TAG, "rt_coap_block_receive_list", OCF_ERROR);
	RT_VERIFY_NON_NULL_RET(rt_block_response_info_list, TAG, "rt_block_response_info_list", OCF_ERROR);
	RT_VERIFY_NON_NULL(packet, TAG, "packet");
	RT_VERIFY_NON_NULL(endpoint, TAG, "endpoint");

	if (!IS_OPTION(packet, COAP_OPTION_BLOCK1) && !IS_OPTION(packet, COAP_OPTION_BLOCK2)) {
		RT_LOG_D(TAG, "This packet is not blockwised packet.");
		return OCF_OK;
	}

	*block_data = NULL;

	uint32_t num = 0;
	uint8_t more = 0;
	uint16_t size = 0;
	uint32_t offset = 0;
	coap_option_t block_option = COAP_OPTION_BLOCK1;
	if (IS_OPTION(packet, COAP_OPTION_BLOCK1) && !IS_OPTION(packet, COAP_OPTION_BLOCK2)) {
		if (0 == rt_coap_get_header_block1(packet, &num, &more, &size, &offset)) {
			RT_LOG_E(TAG, "rt_coap_get_header_block1 failed!");
			return OCF_ERROR;
		}
		block_option = COAP_OPTION_BLOCK1;
	} else if (IS_OPTION(packet, COAP_OPTION_BLOCK2)) {
		if (0 == rt_coap_get_header_block2(packet, &num, &more, &size, &offset)) {
			RT_LOG_E(TAG, "rt_coap_get_header_block2 failed!");
			return OCF_ERROR;
		}
		block_option = COAP_OPTION_BLOCK2;
	}
	RT_LOG_D(TAG, "[C%sS]Received blockwise packet: [%d]more:%d, size:%d, offset:%d", (COAP_OPTION_BLOCK1 == block_option) ? "->" : "<-",
			num, more, size, offset);

	rt_coap_receive_block_s *receive_block = NULL;
	if (!rt_coap_block_find_block_item(rt_coap_block_receive_list, block_option, packet->token, endpoint, (void **)&receive_block)) {
		if (0 != num) {
			RT_LOG_E(TAG, "Wrong packet received!");
			rt_send_error_response(packet, endpoint, REQUEST_ENTITY_INCOMPLETE_4_08);
			return OCF_COMM_ERROR;
		}

		receive_block = (rt_coap_receive_block_s *) rt_mem_alloc(sizeof(rt_coap_receive_block_s));
		RT_VERIFY_NON_NULL_RET(receive_block, TAG, "receive_block", OCF_MEM_FULL);

		receive_block->offset = 0;
		rt_mem_cpy(&receive_block->endpoint, endpoint, sizeof(ocf_endpoint_s));
		rt_coap_copy_token(&receive_block->token, &packet->token);
		receive_block->uri_path = (char *)rt_mem_dup(packet->uri_path, packet->uri_path_len + 1);
		if ((COAP_OPTION_BLOCK1 == block_option) && rt_coap_get_header_size1(packet, &receive_block->packet_len)) {
			receive_block->packet = (uint8_t *) rt_mem_alloc(sizeof(uint8_t) * receive_block->packet_len);
		} else if ((COAP_OPTION_BLOCK2 == block_option) && rt_coap_get_header_size2(packet, &receive_block->packet_len)) {
			receive_block->packet = (uint8_t *) rt_mem_alloc(sizeof(uint8_t) * receive_block->packet_len);
		} else {
			RT_LOG_D(TAG, "can't get size option! alloc default block size : %d", BLOCK_SIZE);
			//TODO: alloc default size and realloc when packet received.
			return OCF_COMM_ERROR;	//TODO: need to remove
		}
		RT_VERIFY_NON_NULL_RET(receive_block->packet, TAG, "receive_block->packet", OCF_MEM_FULL);

		if (size > BLOCK_SIZE) {
			//TODO : negotiation.
			rt_send_error_response(packet, endpoint, REQUEST_ENTITY_TOO_LARGE_4_13);
			return OCF_COMM_ERROR;
		} else {
			receive_block->block_size = size;
		}

		rt_list_insert(rt_coap_block_receive_list, &receive_block->node);
	} else {
		if (receive_block->offset + packet->payload_len > receive_block->packet_len) {
			RT_LOG_E(TAG, "Exceed total packet size!");
			rt_send_error_response(packet, endpoint, REQUEST_ENTITY_INCOMPLETE_4_08);
			rt_remove_receive_block_node(&receive_block->node);
			return OCF_COMM_ERROR;
		}

		if (receive_block->num + 1 != num) {
			RT_LOG_E(TAG, "Expected block num:%d, Real block num:%d", receive_block->num + 1, num);
			rt_send_error_response(packet, endpoint, REQUEST_ENTITY_INCOMPLETE_4_08);
			rt_remove_receive_block_node(&receive_block->node);
			return OCF_COMM_ERROR;
		}

	}

	receive_block->mid = packet->mid;
	receive_block->num = num;
	rt_mem_cpy(receive_block->packet + receive_block->offset, packet->payload, packet->payload_len);
	receive_block->offset += packet->payload_len;

	//finish
	if (0 == more) {
		if (receive_block->offset == receive_block->packet_len) {
			RT_LOG_D(TAG, "Packet receive complete!");
	
			rt_data_s *new_data = rt_receive_data_make_item_without_payload(packet);
			RT_VERIFY_NON_NULL_RET(new_data, TAG, "new_data", OCF_MEM_FULL);
	
			new_data->payload = NULL;
			new_data->payload_len = 0;
			if (receive_block->packet && receive_block->packet_len > 0) {
				new_data->payload_len = receive_block->packet_len;
				new_data->payload = rt_mem_dup(receive_block->packet, receive_block->packet_len);
				if (!new_data->payload) {
					RT_LOG_E(TAG, "new_data->payload alloc failed!");
					rt_data_free_item(new_data);
					return OCF_MEM_FULL;
				}
			}

			if (COAP_OPTION_BLOCK1 == block_option) {
				new_data->flags |= RT_OPTION_BLOCK;
				rt_block_response_info_s *response_info = (rt_block_response_info_s *)rt_mem_alloc(sizeof(rt_block_response_info_s));
				if (!response_info) {
					RT_LOG_E(TAG, "response_info alloc failed!");
					rt_data_free_item(new_data);
					return OCF_MEM_FULL;
				}
				rt_mem_cpy(&response_info->endpoint, endpoint, sizeof(ocf_endpoint_s));
				rt_coap_copy_token(&response_info->token, &packet->token);
				response_info->num = receive_block->num;
				response_info->block_size = receive_block->block_size;
				RT_LOG_D(TAG, "set response info about block transfer");

				rt_list_insert(rt_block_response_info_list, &response_info->node);
			}

			*block_data = new_data;
			rt_remove_receive_block_node(&receive_block->node);
		} else {
			RT_LOG_E(TAG, "Packet receive incomplete!");
			rt_send_error_response(packet, endpoint, REQUEST_ENTITY_INCOMPLETE_4_08);
			rt_remove_receive_block_node(&receive_block->node);
			return OCF_COMM_ERROR;
		}
	} else if (COAP_OPTION_BLOCK1 == block_option) {
		coap_packet_t msg[1];
		uint8_t payload[COAP_MAX_PACKET_SIZE + 1];
		uint16_t payload_len;

		/* Response with CONTINUE_2_31 */
		RT_LOG_D(TAG, "[C<-S]Send ack:[%d]more:%d, num:%d, szx:%d", num, more, num, size);
		coap_message_type_t type = packet->type == COAP_TYPE_CON ? COAP_TYPE_ACK : COAP_TYPE_NON;
		rt_coap_init_message(msg, type, CONTINUE_2_31, receive_block->mid);
		rt_coap_copy_token(&msg->token, &receive_block->token);

		if (0 == rt_coap_set_header_block1(msg, receive_block->num, more, receive_block->block_size)) {
			RT_LOG_E(TAG, "rt_coap_set_header_block1 failed!");
			return OCF_ERROR;
		}

		if (0 == (payload_len = rt_coap_serialize_message(msg, payload))) {
			RT_LOG_E(TAG, "rt_coap_serialize_message failed!");
			return OCF_ERROR;
		}
		
		rt_coap_send_message(payload, payload_len, endpoint);
	} else if (COAP_OPTION_BLOCK2 == block_option) {
		coap_transaction_t *t = rt_coap_get_request_transaction_by_mid(receive_block->mid);
		RT_VERIFY_NON_NULL(t, TAG, "t");

		uint8_t request_packet[COAP_MAX_PACKET_SIZE + 1] = {0, };
		rt_mem_cpy(request_packet, t->packet, t->packet_len);

		coap_packet_t msg[1];
		if (NO_ERROR != rt_coap_parse_message(msg, request_packet, t->packet_len)) {
			RT_LOG_E(TAG, "rt_coap_parse_message failed!");
			return OCF_ERROR;
		}

		uint16_t mid = rt_coap_get_mid();
		coap_transaction_t *new_transaction = rt_coap_new_transaction(COAP_TRANSACTION_REQUEST, mid, endpoint);
		RT_VERIFY_NON_NULL_RET(new_transaction, TAG, "new_transaction", OCF_MEM_FULL);

		RT_LOG_D(TAG, "[C->S]Send client response:[%d]more:%d, size:%d, offset:%d", receive_block->num + 1, 0, size, offset);
	
		rt_coap_set_mid(msg, mid);
		rt_coap_copy_token(&msg->token, &receive_block->token);
		if (0 == rt_coap_set_header_block2(msg, receive_block->num + 1, 0, receive_block->block_size)) {
			RT_LOG_E(TAG, "rt_coap_set_header_block2 failed!");
			return OCF_ERROR;
		}

		if (IS_OPTION(msg, COAP_OPTION_BLOCK1)) {
			RT_LOG_D(TAG, "Remove useless block1 option in packet.");
			UNSET_OPTION(msg, COAP_OPTION_BLOCK1);
		}

		if (msg->payload) {
			msg->payload = NULL;
			msg->payload_len = 0;
		}
		
		ocf_result_t ret = rt_coap_serialize_message_n_set_signal(msg, new_transaction);
		if (OCF_OK != ret) {
			RT_LOG_E(TAG, "rt_coap_serialize_message_n_set_signal failed!");
			return OCF_ERROR;
		}
	}

	return OCF_OK;
}

static ocf_result_t rt_coap_make_block_packet(rt_coap_send_block_s *block_item)
{
	coap_packet_t msg[1];

	coap_transaction_type_t trans_type = block_item->data.flags & RT_OPTION_TRANSACTION_REQUEST ? COAP_TRANSACTION_REQUEST : COAP_TRANSACTION_RESPONSE;
	if (COAP_TRANSACTION_REQUEST == trans_type) {
		block_item->data.mid = rt_coap_get_mid();
	}

	rt_coap_init_message(msg, block_item->data.type, block_item->data.code, block_item->data.mid);
	rt_coap_set_header_uri_path(msg, block_item->data.uri_path);
	rt_coap_copy_token(&msg->token, &block_item->data.token);

	if (RT_OPTION_OBSERVE & block_item->data.flags) {
		rt_coap_set_header_observe(msg, block_item->data.observe_num);
	}

	if (COAP_TRANSACTION_REQUEST == trans_type) {
		coap_content_format_t accept = 0;
		if (OCF_1_0_0 == block_item->data.accept) {
			accept = APPLICATION_VND_OCF_CBOR;
			rt_coap_set_header_accept(msg, accept);
			rt_coap_set_header_ocf_accept(msg, block_item->data.accept);
		} else if (OIC_1_1_0 == block_item->data.accept) {
			accept = APPLICATION_CBOR;
			rt_coap_set_header_accept(msg, accept);
			rt_coap_set_header_ocf_accept(msg, block_item->data.accept);
		}
	}
	rt_coap_set_header_content_format(msg, APPLICATION_VND_OCF_CBOR);

	if (block_item->data.query) {
		rt_coap_set_header_uri_query(msg, block_item->data.query);
	}

	RT_LOG_D(TAG, "mid : %d", block_item->data.mid);
	RT_LOG_D(TAG, "uri_path : %s", block_item->data.uri_path);
	RT_LOG_D(TAG, "token : 0x%x", block_item->data.token.token[0]);

	size_t block_len;
	uint8_t more;
	if ((block_item->data.payload_len - block_item->offset) <= block_item->block_size) {
		more = 0;
		block_len = block_item->data.payload_len - block_item->offset;
	} else {
		more = 1;
		block_len = block_item->block_size;
	}
	
	RT_LOG_D(TAG, "[C%sS]Send blockwise packet: [%d]more:%d, left len:%d, block len:%d", (COAP_TRANSACTION_REQUEST == trans_type) ? "->" : "<-",
			block_item->num, more, block_item->data.payload_len - block_item->offset, block_len);

	if (COAP_TRANSACTION_REQUEST == trans_type) {
		if (0 == block_item->num) {
			rt_coap_set_header_size1(msg, block_item->data.payload_len);
		}

		if (0 == rt_coap_set_header_block1(msg, block_item->num, more, block_item->block_size)) {
			RT_LOG_E(TAG, "rt_coap_set_header_block1 failed!");
			return OCF_ERROR;
		}
	} else if (COAP_TRANSACTION_RESPONSE == trans_type) {
		if (0 == block_item->num) {
			rt_coap_set_header_size2(msg, block_item->data.payload_len);
		}

		if (0 == rt_coap_set_header_block2(msg, block_item->num, more, block_item->block_size)) {
			RT_LOG_E(TAG, "rt_coap_set_header_block2 failed!");
			return OCF_ERROR;
		}
	} else {
		RT_LOG_E(TAG, "Invaild block option!");
		return OCF_ERROR;
	}

	coap_content_format_t content_format = 0;
	if (OCF_1_0_0 == block_item->data.content_format) {
		content_format = APPLICATION_VND_OCF_CBOR;
	} else if (OIC_1_1_0 == block_item->data.content_format) {
		content_format = APPLICATION_CBOR;
	} else {
		RT_LOG_E(TAG, "Unsupported version!");
		return OCF_ERROR;
	}

	if (RT_OPTION_BLOCK & block_item->data.flags) {
		if (OCF_OK != rt_coap_set_block_response_info(msg, &block_item->data, &block_item->endpoint)) {
			RT_LOG_E(TAG, "rt_coap_set_block_response_info failed!");
			return OCF_ERROR;
		}
		block_item->data.flags &= ~RT_OPTION_BLOCK;
	}

	rt_coap_set_header_content_format(msg, content_format);
	rt_coap_set_header_ocf_content_format(msg, block_item->data.content_format);
	rt_coap_set_payload(msg, block_item->data.payload + block_item->offset, block_len);

	coap_transaction_t *t = rt_coap_new_transaction(trans_type, block_item->data.mid, &block_item->endpoint);
	RT_VERIFY_NON_NULL_RET(t, TAG, "transaction is null", OCF_MEM_FULL);

	ocf_result_t ret = rt_coap_serialize_message_n_set_signal(msg, t);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_coap_serialize_message_n_set_signal failed!");
		return OCF_ERROR;
	}

	block_item->offset += block_len;

	if (COAP_TRANSACTION_RESPONSE == trans_type && 0 == more) {
		if (block_item->offset == block_item->data.payload_len) {
			if (OCF_OK != rt_coap_block_remove_send_block(block_item->data.flags, block_item->data.token, &block_item->endpoint)) {
				RT_LOG_E(TAG, "Wrong block packet response is received! ignore!");
				return OCF_ERROR;
			}
		} else {
			RT_LOG_E(TAG, "Wrong block packet made!");
			return OCF_ERROR;
		}
	}

	return OCF_OK;
}

static rt_coap_send_block_s *make_block_item(const rt_data_s *data, const ocf_endpoint_s *endpoint)
{
	rt_coap_send_block_s *block_item = (rt_coap_send_block_s *) rt_mem_alloc(sizeof(rt_coap_send_block_s));
	RT_VERIFY_NON_NULL_RET(block_item, TAG, "block_item", NULL);

	rt_mem_cpy(&block_item->endpoint, endpoint, sizeof(ocf_endpoint_s));
	ocf_result_t ret = rt_data_clone(&block_item->data, data);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_data_clone failed!");
		send_block_item_release(block_item);
		rt_mem_free(block_item);
		block_item = NULL;
		return NULL;
	}
	block_item->offset = block_item->num = 0;
	block_item->block_size = BLOCK_SIZE;

	rt_timer_set(&block_item->ttl, TTL_INTERVAL * RT_CLOCK_SECOND);

	return block_item;
}

static ocf_result_t rt_coap_block_check_duplicate_send_block(const rt_data_s *data, const ocf_endpoint_s *endpoint)
{
	rt_node_s *itr = rt_coap_block_send_list->head;

	while (itr) {
		rt_coap_send_block_s *var = (rt_coap_send_block_s *) rt_list_get_item(rt_coap_block_send_list, itr);
		if ((data->flags & var->data.flags) && rt_coap_compare_token(&data->token, &var->data.token) && rt_endpoint_is_equal(endpoint, &var->endpoint)) {
			RT_LOG_E(TAG, "Can't make duplicate send block!");
			RT_LOG_E(TAG, "Token[0x%x]", data->token.token[0]);
			return OCF_DUPLICATE_REQUEST;
		} else if (var->ttl.interval != 0 && rt_timer_expired(&var->ttl)) {
			RT_LOG_D(TAG, "Send block packet's[0x%x] ttl is expired!", var->data.token.token[0]);
			//TODO: Error handling
			rt_coap_send_block_s *info = (rt_coap_send_block_s *) rt_list_delete_by_node(rt_coap_block_send_list, &var->node);
			if (info) {
				send_block_item_release(info);
				rt_mem_free(info);
				info = NULL;
			}
		}
		itr = itr->next;
	}

	return OCF_OK;
}

ocf_result_t rt_coap_new_block_transaction(const rt_data_s *data, const ocf_endpoint_s *endpoint)
{
	RT_VERIFY_NON_NULL_RET(rt_coap_block_send_list, TAG, "rt_coap_block_send_list", OCF_ERROR);
	RT_VERIFY_NON_NULL(data, TAG, "data");
	RT_VERIFY_NON_NULL(endpoint, TAG, "endpoint");
	RT_VERIFY_NON_NULL(data->token.token, TAG, "data->token");
	RT_VERIFY_NON_NULL(data->uri_path, TAG, "data->uri_path");
	RT_VERIFY_NON_NULL(data->payload, TAG, "data->payload");

	if (endpoint->flags & OCF_TCP) {
		RT_LOG_D(TAG, "TCP transport don't need block transfer!");
		return OCF_INVALID_PARAM;
	}

	if (data->payload_len <= BLOCK_SIZE) {
		RT_LOG_D(TAG, "don't need blockwise transfer.");
		return OCF_INVALID_PARAM;
	}

	if (COAP_TYPE_CON > data->type || COAP_TYPE_ACK < data->type) {
		RT_LOG_E(TAG, "Invaild type.");
		return OCF_INVALID_PARAM;
	}

	ocf_result_t ret = rt_coap_block_check_duplicate_send_block(data, endpoint);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "Duplicate packet!");
		return ret;
	}
	
	
	rt_coap_send_block_s *block_item = make_block_item(data, endpoint);
	if (!block_item) {
		RT_LOG_E(TAG, "make_block_item failed!");
		return OCF_ERROR;
	}

	ret = rt_coap_make_block_packet(block_item);
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_coap_make_block_packet failed!");
		send_block_item_release(block_item);
		rt_mem_free(block_item);
		block_item = NULL;
		return ret;
	}
	
	rt_list_insert(rt_coap_block_send_list, &block_item->node);
	
	return OCF_OK;
}

ocf_result_t rt_coap_block_response_handler(coap_packet_t *packet, const ocf_endpoint_s *endpoint)
{
	RT_VERIFY_NON_NULL_RET(rt_coap_block_send_list, TAG, "rt_coap_block_send_list", OCF_ERROR);
	RT_VERIFY_NON_NULL(packet, TAG, "packet");
	RT_VERIFY_NON_NULL(endpoint, TAG, "endpoint");

	if (!IS_OPTION(packet, COAP_OPTION_BLOCK1) && !IS_OPTION(packet, COAP_OPTION_BLOCK2)) {
		RT_LOG_D(TAG, "This packet is not blockwised packet.");
		return OCF_OK;
	}

	uint32_t num = 0;
	uint8_t more = 0;
	uint16_t size = 0;
	uint32_t offset = 0;
	coap_option_t block_option = COAP_OPTION_BLOCK1;
	if (IS_OPTION(packet, COAP_OPTION_BLOCK1)) {
		if (0 == rt_coap_get_header_block1(packet, &num, &more, &size, &offset)) {
			RT_LOG_E(TAG, "rt_coap_get_header_block1 failed!");
			return OCF_ERROR;
		}
		block_option = COAP_OPTION_BLOCK1;
		RT_LOG_D(TAG, "[C<-S]Received ack:[%d]more:%d, size:%d, offset:%d", num, more, size, offset);
	} else if (IS_OPTION(packet, COAP_OPTION_BLOCK2)) {
		if (0 == rt_coap_get_header_block2(packet, &num, &more, &size, &offset)) {
			RT_LOG_E(TAG, "rt_coap_get_header_block2 failed!");
			return OCF_ERROR;
		}
		block_option = COAP_OPTION_BLOCK2;
		RT_LOG_D(TAG, "[C->S]Received client response:[%d]more:%d, size:%d, offset:%d", num, more, size, offset);
	}

	rt_coap_send_block_s *block_item = NULL;
	if (!rt_coap_block_find_block_item(rt_coap_block_send_list, block_option, packet->token, endpoint, (void **)&block_item)) {
		RT_LOG_E(TAG, "Wrong packet received!");
		return OCF_COMM_ERROR;
	}

	uint32_t compare_num = (COAP_OPTION_BLOCK1 == block_option) ? block_item->num : block_item->num + 1;
	if (compare_num != num) {
		RT_LOG_E(TAG, "Expected block num:%d, Real block num:%d", compare_num, num);
		//TODO : Error handling
		rt_remove_send_block_node(&block_item->node);
		return OCF_COMM_ERROR;
	}

	//Block1 finish packet check.
	if (COAP_OPTION_BLOCK1 == block_option && 0 == more) {
		ocf_result_t ret = rt_coap_block_remove_send_block(block_item->data.flags, packet->token, endpoint);
		if (OCF_OK == ret) {
			UNSET_OPTION(packet, COAP_OPTION_BLOCK1);
		}
	} else {
		if (MAX_BLOCK_COUNT <= block_item->num) {
			RT_LOG_E(TAG, "block number must not bigger than MAX_BLOCK_COUNT(0xFFFFF)!");
			//TODO : Error handling
			rt_remove_send_block_node(&block_item->node);
			return OCF_COMM_ERROR;
		} else {
			block_item->num++;
		}
		// TODO: Compare offset to negotiate block size.
	
		if (COAP_OPTION_BLOCK2 == block_option) {
			block_item->data.mid = packet->mid;
		}
		
		if (OCF_OK != rt_coap_make_block_packet(block_item)) {
			RT_LOG_E(TAG, "rt_coap_make_block_packet failed!");
			//TODO : Error handling
			rt_remove_send_block_node(&block_item->node);
			return OCF_COMM_ERROR;
		}
	}

	return OCF_OK;
}

ocf_result_t rt_coap_block_error_response_handler(coap_packet_t *packet, const ocf_endpoint_s *endpoint)
{
	RT_VERIFY_NON_NULL(packet, TAG, "packet");
	RT_VERIFY_NON_NULL(endpoint, TAG, "endpoint");

	coap_option_t block_option = COAP_OPTION_BLOCK1;
	if (IS_OPTION(packet, COAP_OPTION_BLOCK1)) {
		block_option = COAP_OPTION_BLOCK1;
	} else if (IS_OPTION(packet, COAP_OPTION_BLOCK2)) {
		block_option = COAP_OPTION_BLOCK2;
	}

	rt_coap_send_block_s *block_item = NULL;
	if (!rt_coap_block_find_block_item(rt_coap_block_send_list, block_option, packet->token, endpoint, (void **)&block_item)) {
		RT_LOG_E(TAG, "Wrong packet received!");
		return OCF_COMM_ERROR;
	}

	if (REQUEST_ENTITY_INCOMPLETE_4_08 == packet->code) {
		RT_LOG_D(TAG, "REQUEST_ENTITY_INCOMPLETE_4_08 error response received!");
		RT_LOG_D(TAG, "token[0x%x] packet send very first again!", block_item->data.token.token[0]);
		block_item->offset = block_item->num = 0;
	} else if (REQUEST_ENTITY_TOO_LARGE_4_13 == packet->code) {
		//TODO
	} else {
		RT_LOG_E(TAG, "Unknown error response for block transfer!");
		return OCF_COMM_ERROR;
	}

	if (IS_OPTION(packet, COAP_OPTION_BLOCK2)) {
		block_item->data.mid = packet->mid;
	}
		
	if (OCF_OK != rt_coap_make_block_packet(block_item)) {
		RT_LOG_E(TAG, "rt_coap_make_block_packet failed!");
		//TODO : Error handling
		rt_remove_send_block_node(&block_item->node);
		return OCF_COMM_ERROR;
	}

	return OCF_OK;
}

static ocf_result_t rt_coap_block_list_init(rt_list_s **list, size_t struct_size, uint32_t offset)
{
	*list = (rt_list_s *)rt_mem_alloc(sizeof(rt_list_s));
	if (!*list) {
		RT_LOG_E(TAG, "rt_mem_alloc failed!");
		return OCF_MEM_FULL;
	}
	rt_list_init(*list, struct_size, offset);
	
	return OCF_OK;
}

ocf_result_t rt_coap_init_block(void)
{
	if (rt_coap_block_send_list || rt_coap_block_receive_list || rt_block_response_info_list) {
		RT_LOG_E(TAG, "coap block is already initialized");
		return OCF_ALREADY_INIT;
	}

	ocf_result_t ret = rt_coap_block_list_init(&rt_coap_block_send_list, sizeof(rt_coap_send_block_s), RT_MEMBER_OFFSET(rt_coap_send_block_s, node));
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_coap_block_list_init[rt_coap_block_send_list] failed!");
		rt_coap_terminate_block();
		return ret;
	}

	ret = rt_coap_block_list_init(&rt_coap_block_receive_list, sizeof(rt_coap_receive_block_s), RT_MEMBER_OFFSET(rt_coap_receive_block_s, node));
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_coap_block_list_init[rt_coap_block_receive_list] failed!");
		rt_coap_terminate_block();
		return ret;
	}

	ret = rt_coap_block_list_init(&rt_block_response_info_list, sizeof(rt_block_response_info_s), RT_MEMBER_OFFSET(rt_block_response_info_s, node));
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_coap_block_list_init[rt_block_response_info_list] failed!");
		rt_coap_terminate_block();
		return ret;
	}

	return OCF_OK;
}

void rt_coap_terminate_block(void)
{
	if (rt_coap_block_send_list) {
		rt_list_terminate(rt_coap_block_send_list, send_block_item_release);
		rt_mem_free(rt_coap_block_send_list);
		rt_coap_block_send_list = NULL;
	}
	if (rt_coap_block_receive_list) {
		rt_list_terminate(rt_coap_block_receive_list, receive_block_item_release);
		rt_mem_free(rt_coap_block_receive_list);
		rt_coap_block_receive_list = NULL;
	}
	if (rt_block_response_info_list) {
		rt_list_terminate(rt_block_response_info_list, NULL);
		rt_mem_free(rt_block_response_info_list);
		rt_block_response_info_list = NULL;
	}
}
