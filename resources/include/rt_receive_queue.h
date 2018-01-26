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

#ifndef __RT_OCF_RECEIVE_QUEUE_H
#define __RT_OCF_RECEIVE_QUEUE_H

#include "ocf_types.h"
#include "rt_data_handler.h"

typedef enum {
	RT_REQUEST = 0,
	RT_RESPONSE
} rt_recv_type_t;

typedef struct {
	rt_data_s *packet;
	ocf_endpoint_s endpoint;
	rt_recv_type_t type;
} rt_receive_queue_item_s;

typedef void (*receive_callback)(const rt_data_s *packet, const ocf_endpoint_s * endpoint);

ocf_result_t rt_receive_queue_init(void);
void rt_receive_queue_terminate(void);
ocf_result_t rt_receive_queue_request_enqueue(rt_data_s *packet, const ocf_endpoint_s *endpoint);
ocf_result_t rt_receive_queue_response_enqueue(rt_data_s *packet, const ocf_endpoint_s *endpoint);
ocf_result_t rt_receive_queue_set_request_callback(receive_callback callback);
ocf_result_t rt_receive_queue_set_response_callback(receive_callback callback);

#endif							/* __RT_OCF_RECEIVE_QUEUE_H */
