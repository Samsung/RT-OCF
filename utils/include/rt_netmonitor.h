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

#ifndef RT_NETMONITOR_H_
#define RT_NETMONITOR_H_

#include "ocf_types.h"
#include <errno.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <net/if.h>
#include <netinet/in.h>

typedef ocf_result_t(*rt_adapter_if_state_cb)(ocf_network_status_t status);

#define NETMONITOR  "net_monitor"

void quit_netlink_thread(void);
ocf_result_t rt_init_netmonitor(void);
ocf_result_t rt_terminate_netmonitor(void);
ocf_result_t rt_register_netmonitor(rt_adapter_if_state_cb func);
ocf_result_t rt_unregister_netmonitor(rt_adapter_if_state_cb func);
ocf_result_t rt_change_netmonitor_status(ocf_network_status_t status);

#endif
