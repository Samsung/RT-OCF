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
#include "rt_coap_transactions.h"
//#include "rt_coap_observe.h"  //TODO RT

#include "rt_ssl.h"
#include "rt_mem.h"
#include "rt_utils.h"
#include "rt_event.h"
#include "rt_endpoint.h"

#define TAG "RT_COAP_TR"

static rt_list_s *request_transactions_list = NULL;
static rt_list_s *response_transactions_list = NULL;

coap_transaction_t *rt_coap_new_transaction(coap_transaction_type_t type, uint16_t mid, const ocf_endpoint_s *endpoint)
{
	if (COAP_TRANSACTION_REQUEST == type) {
		RT_VERIFY_NON_NULL_RET(request_transactions_list, TAG, "request_transactions_list", NULL);
	} else if (COAP_TRANSACTION_RESPONSE == type) {
		RT_VERIFY_NON_NULL_RET(response_transactions_list, TAG, "response_transactions_list", NULL);
	} else {
		RT_LOG_E(TAG, "Invalid transaction type!");
		return NULL;
	}

	coap_transaction_t *t = (coap_transaction_t *) rt_mem_alloc(sizeof(coap_transaction_t));
	RT_VERIFY_NON_NULL_RET(t, TAG, "t", NULL);

	if (t) {
		t->type = type;
		t->status = COAP_TRANSACTION_NEED_SEND;
		t->mid = mid;
		t->retrans_counter = 0;

		if (endpoint) {
			t->endpoint = (ocf_endpoint_s *) rt_mem_alloc(sizeof(ocf_endpoint_s));
			if (!t->endpoint) {
				RT_LOG_E(TAG, "t>endpoint memory alloc failed!");
				rt_mem_free(t);
				return NULL;
			}

			rt_mem_cpy(t->endpoint, endpoint, sizeof(ocf_endpoint_s));
		} else {
			t->endpoint = NULL;
		}

		if (COAP_TRANSACTION_REQUEST == t->type) {
			rt_list_insert(request_transactions_list, &(t->node));
		} else if (COAP_TRANSACTION_RESPONSE == t->type) {
			rt_list_insert(response_transactions_list, &(t->node));
		} else {
			RT_LOG_E(TAG, "Invaild transaction type!");
			rt_mem_free(t);
			t = NULL;
		}

		rt_timer_set(&t->ttl, TTL_INTERVAL * RT_CLOCK_SECOND);
	}

	return t;
}

/*---------------------------------------------------------------------------*/
void rt_coap_send_transaction(coap_transaction_t *t)
{
	RT_LOG_D(TAG, "rt_coap_send_transaction IN", t->mid);

	rt_coap_send_message(t->packet, t->packet_len, t->endpoint);

	if (COAP_TYPE_CON == ((COAP_HEADER_TYPE_MASK & t->packet[0]) >> COAP_HEADER_TYPE_POSITION)) {
		if (t->retrans_counter < COAP_MAX_RETRANSMIT) {
			/* not timed out yet */
			//RT_LOG_D(TAG, "Keeping transaction %u", t->mid);

			if (t->retrans_counter == 0) {
				t->retrans_timer.interval = COAP_RESPONSE_TIMEOUT_TICKS + (rt_random_rand()
											% (rt_clock_time_t)
											COAP_RESPONSE_TIMEOUT_BACKOFF_MASK);
				//RT_LOG_D(TAG,"Initial interval %f", (float)t->retrans_timer.interval / RT_CLOCK_SECOND);
			} else {
				t->retrans_timer.interval <<= 1;	/* double */
				//RT_LOG_D(TAG,"Doubled (%u) interval %f", t->retrans_counter, (float)t->retrans_timer.interval / RT_CLOCK_SECOND);
			}

			rt_timer_restart(&t->retrans_timer);	/* interval updated above */
			t = NULL;
		} else {
			/* timed out */
			//RT_LOG_D(TAG,"Timeout");

			// /* handle observers */
			// rt_coap_remove_observer_by_client(&t->addr, t->port);

			rt_coap_clear_transaction(t);
		}
	} else {
		t->status = COAP_TRANSACTION_SEND_DONE;
		if (COAP_TRANSACTION_RESPONSE == t->type) {
			rt_coap_clear_transaction(t);
		}
	}
}

/*---------------------------------------------------------------------------*/
void rt_coap_clear_transaction(coap_transaction_t *t)
{
	RT_VERIFY_NON_NULL_VOID(t, TAG, "t");

	rt_list_s *list = NULL;
	if (COAP_TRANSACTION_REQUEST == t->type) {
		list = request_transactions_list;
	} else if (COAP_TRANSACTION_RESPONSE == t->type) {
		list = response_transactions_list;
	} else {
		return;
	}
	RT_VERIFY_NON_NULL_VOID(list, TAG, "list");

	RT_LOG_D(TAG, "Freeing transaction %u: %p", t->mid, t);

	rt_timer_reset(&t->retrans_timer);
	if (t->endpoint) {
		rt_mem_free(t->endpoint);
	}

	coap_transaction_t *temp = (coap_transaction_t *) rt_list_delete_by_node(list, &(t->node));
	rt_mem_free(temp);
}

coap_transaction_t *rt_coap_get_request_transaction_by_mid(uint16_t mid)
{
	RT_VERIFY_NON_NULL_RET(request_transactions_list, TAG, "request_transactions_list", NULL);
	rt_node_s *itr = request_transactions_list->head;

	while (itr) {
		coap_transaction_t *var = (coap_transaction_t *) rt_list_get_item(request_transactions_list, itr);
		itr = itr->next;
		if (var->mid == mid) {
			RT_LOG_D(TAG, "Found Request transaction for MID %u", var->mid);
			return var;
		}
	}

	return NULL;
}

coap_transaction_t *rt_coap_get_response_transaction_by_mid(uint16_t mid)
{
	RT_VERIFY_NON_NULL_RET(response_transactions_list, TAG, "response_transactions_list", NULL);
	rt_node_s *itr = response_transactions_list->head;

	while (itr) {
		coap_transaction_t *var = (coap_transaction_t *) rt_list_get_item(response_transactions_list, itr);
		itr = itr->next;
		if (var->mid == mid) {
			RT_LOG_D(TAG, "Found Response transaction for MID %u", var->mid);
			return var;
		}
	}

	return NULL;
}

static bool rt_coap_get_nearest_wakeup_time_of_transactions_on_specific_list(rt_list_s *list, rt_clock_time_t *wakeup_time)
{
	RT_VERIFY_NON_ZERO_RET(list, TAG, NULL, false);
	RT_VERIFY_NON_ZERO_RET(list->count, TAG, NULL, false);

	bool ret = false;
	rt_clock_time_t internal_wakeup_time;

	rt_node_s *itr = list->head;

	while (itr) {
		coap_transaction_t *var = (coap_transaction_t *) rt_list_get_item(list, itr);
		RT_VERIFY_NON_NULL_RET(var, TAG, "var", ret);
		itr = itr->next;

		if (var->retrans_timer.interval && COAP_TRANSACTION_SEND_DONE != var->status) {
			internal_wakeup_time = var->retrans_timer.start + var->retrans_timer.interval;
			if (internal_wakeup_time < *wakeup_time || !ret) {
				*wakeup_time = internal_wakeup_time;
				ret = true;
			}
		}
	}

	return ret;
}

bool rt_coap_get_nearest_wakeup_time_of_transactions(rt_clock_time_t *wakeup_time)
{
	RT_VERIFY_NON_NULL_RET(wakeup_time, TAG, NULL, false);

	bool ret = false;

	ret = rt_coap_get_nearest_wakeup_time_of_transactions_on_specific_list(request_transactions_list, wakeup_time);
	ret = rt_coap_get_nearest_wakeup_time_of_transactions_on_specific_list(response_transactions_list, wakeup_time) || ret;

	return ret;

}

/*---------------------------------------------------------------------------*/
static int coap_check_send_finish_transaction(coap_transaction_t *var)
{
	RT_VERIFY_NON_NULL_RET(var, TAG, "var is NULL", 0);

	return (var->status == COAP_TRANSACTION_SEND_DONE);
}

static int coap_check_normal_transactions(coap_transaction_t *var)
{
	RT_VERIFY_NON_NULL_RET(var, TAG, "var is NULL", 0);

	return (var->retrans_timer.interval == 0 && var->packet_len > 0);
}

static int coap_check_retransmissions(coap_transaction_t *var)
{
	RT_VERIFY_NON_NULL_RET(var, TAG, "var is NULL", 0);

	return (var->retrans_timer.interval != 0 && rt_timer_expired(&var->retrans_timer));
}

static int coap_check_endpoint_is_secure(ocf_endpoint_s *endpoint)
{
	RT_VERIFY_NON_NULL_RET(endpoint, TAG, "endpoint is NULL", 0);

	return (endpoint->flags & OCF_SECURE);
}

static void coap_handle_secure_transactions(coap_transaction_t *var)
{
	RT_VERIFY_NON_NULL_VOID(var, TAG, "var is NULL");

	rt_ssl_state_t ssl_state = RT_SSL_HANDSHAKE_NON;

	rt_ssl_check_session(var->endpoint, &ssl_state);
	if (RT_SSL_HANDSHAKE_NON == ssl_state) {
		rt_endpoint_log(OCF_LOG_DEBUG, "trigerring handshake to", var->endpoint);
		rt_ssl_initialize_handshake(var->endpoint);
	} else if (RT_SSL_HANDSHAKE_OVER == ssl_state) {
		RT_LOG_D(TAG, "Transmitting %u", var->mid);
		rt_coap_send_transaction(var);
	} else if (RT_SSL_HANDSHAKE_FAILURE == ssl_state) {
		RT_LOG_D(TAG, "Handshake failure");
	}
}

static void handshake_fail_callback(const ocf_endpoint_s *endpoint)
{
	RT_LOG_D(TAG, "%s IN", __func__);
	rt_node_s *itr = request_transactions_list->head;

	while (itr) {
		coap_transaction_t *var = (coap_transaction_t *) rt_list_get_item(request_transactions_list, itr);
		itr = itr->next;
		if (coap_check_normal_transactions(var)) {
			if (coap_check_endpoint_is_secure(var->endpoint) && rt_endpoint_is_equal(endpoint, var->endpoint)) {
				//TODO: Call error handler for Application
				rt_endpoint_log(OCF_LOG_ERROR, "failed handshake with", var->endpoint);
				rt_coap_clear_transaction(var);
			}
		}
	}
	RT_LOG_D(TAG, "%s OUT", __func__);
}

static void rt_coap_check_ttl(coap_transaction_t *transaction)
{
	RT_VERIFY_NON_NULL_VOID(transaction, TAG, "transaction");

	if (transaction->ttl.interval != 0 && rt_timer_expired(&transaction->ttl)) {
		if (transaction->endpoint) {
			rt_endpoint_log(OCF_LOG_DEBUG, TAG, transaction->endpoint);
		} else {
			RT_LOG_D(TAG, "Multicast packet");
		}
		RT_LOG_D(TAG, "\t - transaction %u ttl is expired!", transaction->mid);
		rt_coap_clear_transaction(transaction);
	}
}

static void rt_coap_check_transactions_on_specific_list(rt_list_s *list)
{
	// RT_LOG_D(TAG, "%s IN", __func__);
	RT_VERIFY_NON_NULL_VOID(list, TAG, "list");

	if (list->count == 0) {
		return;
	}

	rt_node_s *itr = list->head;

	while (itr) {
		coap_transaction_t *var = (coap_transaction_t *) rt_list_get_item(list, itr);
		itr = itr->next;
		if (coap_check_send_finish_transaction(var)) {
			rt_coap_check_ttl(var);
		} else {
			if (coap_check_normal_transactions(var)) {
				if (var->endpoint && coap_check_endpoint_is_secure(var->endpoint)) {	//TODO : Need Request/Response seperate logic.
					coap_handle_secure_transactions(var);
					RT_LOG_D(TAG, "coap_handle_secure_transactions");
				} else {
					RT_LOG_D(TAG, "Transmitting %u", var->mid);
					rt_coap_send_transaction(var);
				}
			} else if (coap_check_retransmissions(var)) {
				++(var->retrans_counter);
				RT_LOG_D(TAG, "Retransmitting %u (%u)", var->mid, var->retrans_counter);
				rt_coap_send_transaction(var);
			}
		}
	}
	// RT_LOG_D(TAG, "%s OUT", __func__);
}

void rt_coap_check_transactions(void)
{
	rt_coap_check_transactions_on_specific_list(request_transactions_list);
	rt_coap_check_transactions_on_specific_list(response_transactions_list);
}

/*---------------------------------------------------------------------------*/
static void rt_coap_release_transaction_item(void *item)
{
	coap_transaction_t *transaction = (coap_transaction_t *) item;
	RT_VERIFY_NON_NULL_VOID(transaction, TAG, "item is NULL");

	rt_mem_free(transaction->endpoint);
}

static ocf_result_t rt_coap_trancaction_list_init(rt_list_s **list, size_t struct_size, uint32_t offset)
{
	*list = (rt_list_s *)rt_mem_alloc(sizeof(rt_list_s));
	if (!*list) {
		RT_LOG_E(TAG, "rt_mem_alloc failed!");
		return OCF_MEM_FULL;
	}
	rt_list_init(*list, struct_size, offset);

	return OCF_OK;
}

ocf_result_t rt_coap_init_transaction_list(void)
{
	if (request_transactions_list || response_transactions_list) {
		RT_LOG_E(TAG, "coap transcation is already initialized");
		return OCF_ALREADY_INIT;
	}

	ocf_result_t ret = rt_coap_trancaction_list_init(&request_transactions_list, sizeof(coap_transaction_t), RT_MEMBER_OFFSET(coap_transaction_t, node));
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_coap_trancaction_list_init[request_transactions_list] failed!");
		rt_coap_terminate_transaction_list();
		return ret;
	}

	ret = rt_coap_trancaction_list_init(&response_transactions_list, sizeof(coap_transaction_t), RT_MEMBER_OFFSET(coap_transaction_t, node));
	if (OCF_OK != ret) {
		RT_LOG_E(TAG, "rt_coap_trancaction_list_init[request_transactions_list] failed!");
		rt_coap_terminate_transaction_list();
		return ret;
	}

	rt_ssl_set_handshake_callback(handshake_fail_callback);

	return OCF_OK;
}

void rt_coap_terminate_transaction_list(void)
{
	if (request_transactions_list) {
		rt_list_terminate(request_transactions_list, rt_coap_release_transaction_item);
		rt_mem_free(request_transactions_list);
		request_transactions_list = NULL;
	}
	if (response_transactions_list) {
		rt_list_terminate(response_transactions_list, rt_coap_release_transaction_item);
		rt_mem_free(response_transactions_list);
		response_transactions_list = NULL;
	}
}
