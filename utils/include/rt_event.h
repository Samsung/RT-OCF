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

#ifndef __RT_OCF_EVENT_H
#define __RT_OCF_EVENT_H

#include "ocf_types.h"
#include "rt_timer.h"

ocf_result_t rt_event_init(void);
ocf_result_t rt_event_terminate(void);

int rt_event_timedwait(const rt_clock_time_t timeout);
int rt_event_wait(void);
int rt_event_set_signal(void);

#endif							/* __RT_OCF_EVENT_H */
