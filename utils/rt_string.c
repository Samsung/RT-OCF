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

#include <string.h>

#include "rt_string.h"
#include "rt_utils.h"

#define TAG "RT_STRING"

char *rt_strncpy(char *dest_str, const char *src_str, const size_t len)
{

	RT_VERIFY_NON_NULL_RET(dest_str, TAG, "dest_str is NULL", NULL);
	RT_VERIFY_NON_NULL_RET(src_str, TAG, "src_str is NULL", dest_str);
	RT_VERIFY_NON_ZERO_RET(len, TAG, "len is zero", dest_str);

	RT_VERIFY_NON_NULL_RET(strncpy(dest_str, src_str, len), TAG, "calling is failed", NULL);
	dest_str[len] = '\0';

	return dest_str;

}

char *rt_strcpy(char *dest_str, const char *src_str)
{
	RT_VERIFY_NON_NULL_RET(src_str, TAG, "src_str is NULL", dest_str);

	size_t len = strlen(src_str);

	return rt_strncpy(dest_str, src_str, len);

}
