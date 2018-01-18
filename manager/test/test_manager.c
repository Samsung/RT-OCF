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

#include "unity.h"
#include "unity_fixture.h"
#include <stdio.h>

#include "rt_manager.h"
#include "ocf_resources.h"
#include "ocf_types.h"
#include "test_common.h"

static ocf_persistent_storage_handler_s temp_doxm_handler = { test_doxm_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_cred_handler = { test_cred_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_acl2_handler = { test_acl2_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_pstat_handler = { test_pstat_fopen, fread, fwrite, fclose };

TEST_GROUP(test_manager);

TEST_SETUP(test_manager)
{
	create_security_data_files();
	ocf_sec_register_ps_handler(&temp_doxm_handler, &temp_pstat_handler, &temp_cred_handler, &temp_acl2_handler);	
}

TEST_TEAR_DOWN(test_manager)
{
	ocf_terminate();
	remove_security_data_files();
}

TEST(test_manager, ocf_init_ok)
{
	TEST_ASSERT_EQUAL_INT(OCF_OK, ocf_init(OCF_SERVER, "Samsung", OCF_RES_100 | OCF_SH_100));
}

TEST(test_manager, ocf_init_null_manufacture)
{
	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, ocf_init(OCF_SERVER, NULL, OCF_RES_100 | OCF_SH_100));
}

// set_platform_info information of data :: IP/message/ip..others.
// register_platform_info
// start receive/send/  handler.

TEST_GROUP_RUNNER(test_manager)
{
	RUN_TEST_CASE(test_manager, ocf_init_ok);
	RUN_TEST_CASE(test_manager, ocf_init_null_manufacture);
}

#ifndef CONFIG_IOTIVITY_RT

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_manager);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
