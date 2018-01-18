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

#ifndef __IOTIVITY_RT_SEC_PERSISTENT_STORAGE_H
#define __IOTIVITY_RT_SEC_PERSISTENT_STORAGE_H

#include "ocf_types.h"
#include "rt_rep.h"

typedef enum {
	RT_SEC_DOXM = 0,
	RT_SEC_PSTAT,
	RT_SEC_CRED,
	RT_SEC_ACL2,
	RT_SEC_MAX
} rt_sec_resources_t;

typedef struct {
	FILE *(*open)(const char *path, const char *mode);
	size_t(*read)(void *ptr, size_t size, size_t nmemb, FILE *stream);
	size_t(*write)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
	int (*close)(FILE *fp);
} rt_persistent_storage_handler_s;

ocf_result_t rt_sec_register_ps_handler(rt_persistent_storage_handler_s *ps_doxm, rt_persistent_storage_handler_s *ps_pstat, rt_persistent_storage_handler_s *ps_cred, rt_persistent_storage_handler_s *ps_acl);
ocf_result_t rt_sec_load_ps(const rt_sec_resources_t sec_resource, rt_rep_decoder_s **rep);
ocf_result_t rt_sec_save_ps(const rt_sec_resources_t sec_resource, rt_rep_encoder_s *rep);
#endif
