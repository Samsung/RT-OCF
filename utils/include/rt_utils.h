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

#ifndef __RT_OCF_UTILS_H
#define __RT_OCF_UTILS_H

#include "rt_logger.h"

//Verify the validity of input argument.
#define RT_VERIFY_NON_NULL_RET(arg, tag, log_message, ret) \
	if (!(arg)) { \
		if (!(log_message))  return (ret); \
		RT_LOG_E((tag), "Invalid value: %s", (log_message)); \
		return (ret); \
	} \

#define RT_VERIFY_NON_NULL(arg, tag, log_message) \
	RT_VERIFY_NON_NULL_RET((arg), (tag), (log_message), OCF_INVALID_PARAM)

#define RT_VERIFY_NON_NULL_VOID(arg, tag, log_message) \
	if (!(arg)) { \
		if (!(log_message))  return; \
		RT_LOG_E((tag), "Invalid value: %s", (log_message)); \
		return; \
	} \

#define RT_VERIFY_NON_NULL_EXIT(arg, tag, log_message) \
	do {  \
		if (!(arg)) { \
			if (!(log_message))  goto exit; \
			RT_LOG_E((tag), "Invalid value: %s", log_message); \
			goto exit; \
		} \
	 } while (0)

#define RT_VERIFY_NON_ZERO_RET(arg, tag, log_message, ret) \
	RT_VERIFY_NON_NULL_RET((arg), (tag), (log_message), (ret)) \

#define RT_VERIFY_NON_ZERO_VOID(arg, tag, log_message) \
	RT_VERIFY_NON_NULL_VOID((arg), (tag), (log_message)) \

#endif							/* __RT_OCF_UTILS_H */
