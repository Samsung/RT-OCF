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
 * - ifndef related to struct iovec is deleted.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <pthread.h>

#include "rt_netmonitor.h"
#include "rt_mem.h"
#include "rt_list.h"
#include "rt_logger.h"

typedef struct _network_change_cb_item {
	rt_adapter_if_state_cb adapter;
	rt_node_s node;
} network_change_cb_item_s;

#ifndef FD_SETSIZE
#define FD_SETSIZE 1024
#endif

/* Pthread Signals.  */
#define	SIGHUP		1			/* Hangup (POSIX).  */
#define	SIGINT		2			/* Interrupt (ANSI).  */
#define	SIGQUIT		3			/* Quit (POSIX).  */

int netlink_thread_id;
pthread_t netlink_pthread;
rt_list_s g_netchange_cb_list;
int nl_socket;
char buf[4096];

void quit_netlink_thread(void)
{
	pthread_cancel(netlink_pthread);
}

ocf_result_t rt_change_netmonitor_status(ocf_network_status_t status)
{
	network_change_cb_item_s *var;
	rt_node_s *itr = NULL;
	ocf_result_t result = OCF_OK;

	RT_LOG_D(NETMONITOR, "(%04d) %s: status=%d ", __LINE__, __FUNCTION__, status);

	itr = g_netchange_cb_list.head;

	while (itr) {
		RT_LOG_D(NETMONITOR, "(%04d) %s: itr value: %p!!!! ", __LINE__, __FUNCTION__, itr);
		var = (network_change_cb_item_s *) rt_list_get_item(&g_netchange_cb_list, itr);
		if (OCF_OK != var->adapter(status)) {
			result = OCF_ERROR;
		}
		itr = itr->next;
	}

	return result;
}

ocf_result_t rt_init_netmonitor(void)
{
	RT_LOG_D(NETMONITOR, "(%04d) %s:  ", __LINE__, __FUNCTION__);
	rt_list_init(&g_netchange_cb_list, sizeof(network_change_cb_item_s), RT_MEMBER_OFFSET(network_change_cb_item_s, node));
	assert(0 == g_netchange_cb_list.count);
	assert((void *)0 == g_netchange_cb_list.head);
	assert((void *)0 == g_netchange_cb_list.tail);

	return OCF_OK;
}

ocf_result_t rt_register_netmonitor(rt_adapter_if_state_cb func)
{
	network_change_cb_item_s *ptr = NULL;

	ptr = rt_list_search(&g_netchange_cb_list, RT_MEMBER_OFFSET(network_change_cb_item_s, adapter), RT_MEMBER_SIZE(network_change_cb_item_s, adapter), &func);

	if (!ptr) {
		ptr = (network_change_cb_item_s *) rt_mem_alloc(sizeof(network_change_cb_item_s));
		if (!ptr) {
			RT_LOG_E(NETMONITOR, "cb item mem alloc failed!");
			return OCF_MEM_FULL;
		}
		ptr->adapter = func;
		rt_list_insert(&g_netchange_cb_list, &(ptr->node));

		RT_LOG_D(NETMONITOR, "(%04d) %s: ptr=%p cnt=%d", __LINE__, __FUNCTION__, ptr, g_netchange_cb_list.count);
	}

	RT_LOG_D(NETMONITOR, "(%04d) %s: ptr=%p", __LINE__, __FUNCTION__, ptr);

	return OCF_OK;
}

ocf_result_t rt_unregister_netmonitor(rt_adapter_if_state_cb func)
{
	int before_num_of_callback = g_netchange_cb_list.count;
	network_change_cb_item_s *ptr = NULL;

	RT_LOG_D(NETMONITOR, "(%04d) %s: cnt=%d before", __LINE__, __FUNCTION__, g_netchange_cb_list.count);
	ptr = rt_list_delete(&g_netchange_cb_list, RT_MEMBER_OFFSET(network_change_cb_item_s, adapter), RT_MEMBER_SIZE(network_change_cb_item_s, adapter), &func);

	RT_LOG_D(NETMONITOR, "(%04d) %s: ptr=%p", __LINE__, __FUNCTION__, ptr);
	RT_LOG_D(NETMONITOR, "(%04d) %s: cnt=%d after", __LINE__, __FUNCTION__, g_netchange_cb_list.count);

	if (ptr != NULL) {
		rt_mem_free(ptr);
		RT_LOG_D(NETMONITOR, "(%04d) %s: cnt=%d", __LINE__, __FUNCTION__, g_netchange_cb_list.count);

		if (before_num_of_callback - 1 == g_netchange_cb_list.count) {
			return OCF_OK;
		} else {
			return OCF_ERROR;
		}
	} else {

		RT_LOG_D(NETMONITOR, "(%04d) %s: cnt=%d", __LINE__, __FUNCTION__, g_netchange_cb_list.count);

		// not exist
		return OCF_ERROR;
	}
}

ocf_result_t rt_terminate_netmonitor(void)
{
	network_change_cb_item_s *var;
	rt_node_s *itr = NULL;

	itr = g_netchange_cb_list.head;

	while (itr) {
		RT_LOG_D(NETMONITOR, "(%04d) %s: itr value: %p!!!!", __LINE__, __FUNCTION__, itr);
		RT_LOG_D(NETMONITOR, "(%04d) %s: cnt=%d", __LINE__, __FUNCTION__, g_netchange_cb_list.count);
		var = (network_change_cb_item_s *) rt_list_delete_by_node(&g_netchange_cb_list, itr);
		itr = itr->next;
		rt_mem_free(var);
	}

	int status;
	pthread_join(netlink_pthread, (void **)&status);

	if (nl_socket) {
		close(nl_socket);
		nl_socket = 0;
	}

	return OCF_OK;
}
