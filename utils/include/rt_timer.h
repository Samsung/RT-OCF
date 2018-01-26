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
 * - struct timer and clock_time_t is renamed.
 * - All functions are renamed.
 */

/*
 * Copyright (c) 2004, Swedish Institute of Computer Science.
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
 *
 * Author: Adam Dunkels <adam@sics.se>
 *
 */

/**
 * \defgroup timer Timer library
 *
 * The Contiki kernel does not provide support for timed
 * events. Rather, an application that wants to use timers needs to
 * explicitly use the timer library.
 *
 * The timer library provides functions for setting, resetting and
 * restarting timers, and for checking if a timer has expired. An
 * application must "manually" check if its timers have expired; this
 * is not done automatically.
 *
 * A timer is declared as a \c struct \c timer and all access to the
 * timer is made by a pointer to the declared timer.
 *
 * \note The timer library is not able to post events when a timer
 * expires. The \ref etimer "Event timers" should be used for this
 * purpose.
 *
 * \note The timer library uses the \ref clock "Clock library" to
 * measure time. Intervals should be specified in the format used by
 * the clock library.
 *
 * \sa \ref etimer "Event timers"
 *
 * @{
 */

#ifndef __RT_OCF_TIMER_H
#define __RT_OCF_TIMER_H

#include <stdint.h>
#include <time.h>

#define RT_CLOCK_SECOND CLOCKS_PER_SEC

typedef uint64_t rt_clock_time_t;

/**
 * A timer.
 *
 * This structure is used for declaring a timer. The timer must be set
 * with timer_set() before it can be used.
 *
 * \hideinitializer
 */
typedef struct {
	rt_clock_time_t start;
	rt_clock_time_t interval;
} rt_timer_s;

rt_clock_time_t rt_clock_time(void);
void rt_timer_set(rt_timer_s *t, rt_clock_time_t interval);
void rt_timer_reset(rt_timer_s *t);
void rt_timer_restart(rt_timer_s *t);
int rt_timer_expired(rt_timer_s *t);
rt_clock_time_t rt_timer_remaining(rt_timer_s *t);

#endif							/* __RT_OCF_TIMER_H */
