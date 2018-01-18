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

#ifndef __IOTIVITY_RT_TEST_COMMON_H
#define __IOTIVITY_RT_TEST_COMMON_H

#include <fcntl.h>
#include <stdio.h>
#include <pthread.h>

#include "ocf_types.h"

#define WAIT_TIME_SECONDS 5

#ifdef CONFIG_IOTIVITY_RT
static const char TEMP_DOXM_PATH[] = "/mnt/test_svr_doxm.dat";
static const char TEMP_CRED_PATH[] = "/mnt/test_svr_cred.dat";
static const char TEMP_ACL2_PATH[] = "/mnt/test_svr_acl2.dat";
static const char TEMP_PSTAT_PATH[] = "/mnt/test_svr_pstat.dat";
#else
static const char TEMP_DOXM_PATH[] = "test_svr_doxm.dat";
static const char TEMP_CRED_PATH[] = "test_svr_cred.dat";
static const char TEMP_ACL2_PATH[] = "test_svr_acl2.dat";
static const char TEMP_PSTAT_PATH[] = "test_svr_pstat.dat";
#endif

FILE *test_doxm_fopen(const char *path, const char *mode);
FILE *test_cred_fopen(const char *path, const char *mode);
FILE *test_acl2_fopen(const char *path, const char *mode);
FILE *test_pstat_fopen(const char *path, const char *mode);

void create_security_data_files(void);
void remove_security_data_files(void);

int wait_for_condition(pthread_mutex_t *mutex, pthread_cond_t *cond);
#endif
