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

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_manager);
	RUN_TEST_GROUP(test_coap);
	RUN_TEST_GROUP(test_coap_block);
	RUN_TEST_GROUP(test_ssl_client);
	RUN_TEST_GROUP(test_ssl_common);
	RUN_TEST_GROUP(test_ssl_server);
	RUN_TEST_GROUP(test_transport);
	RUN_TEST_GROUP(test_cbor);
	RUN_TEST_GROUP(test_core_device);
	RUN_TEST_GROUP(test_core_introspection);
	RUN_TEST_GROUP(test_core_platform_with_ocf_init);
	RUN_TEST_GROUP(test_core_resource_with_ocf_init);
	RUN_TEST_GROUP(test_receive_queue);
	RUN_TEST_GROUP(test_rep);
	RUN_TEST_GROUP(test_request);
	RUN_TEST_GROUP(test_resources);
	RUN_TEST_GROUP(test_sec_acl2_resource);
	RUN_TEST_GROUP(test_sec_cred_resource);
	RUN_TEST_GROUP(test_sec_doxm_resource);
	RUN_TEST_GROUP(test_sec_persistent_storage);
	RUN_TEST_GROUP(test_sec_pstat_resource);
	RUN_TEST_GROUP(test_data_handler);
	RUN_TEST_GROUP(test_endpoint);
	RUN_TEST_GROUP(test_event);
	RUN_TEST_GROUP(test_list);
	RUN_TEST_GROUP(test_logger);
	RUN_TEST_GROUP(test_message_queue);
	RUN_TEST_GROUP(test_queue);
	RUN_TEST_GROUP(test_random);
	RUN_TEST_GROUP(test_string);
	RUN_TEST_GROUP(test_thread);
	RUN_TEST_GROUP(test_timer);
	RUN_TEST_GROUP(test_url);
	RUN_TEST_GROUP(test_uuid);
}

int test_runner(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}
