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

#include "test_common.h"
#include "ocf_resources.h"

#include "rt_logger.h"

#define TAG "TC_COLLECTION"

static ocf_persistent_storage_handler_s temp_doxm_handler = { test_doxm_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_cred_handler = { test_cred_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_acl2_handler = { test_acl2_fopen, fread, fwrite, fclose };
static ocf_persistent_storage_handler_s temp_pstat_handler = { test_pstat_fopen, fread, fwrite, fclose };

#define RES_LIGHT "/light/1"
#define RES_FAN "/fan/1"
#define RES_SPEAKER "/speaker/1"
#define RES_ROOM "/room"

ocf_endpoint_s g_endpoint;

TEST_GROUP(test_col_creating_links);
TEST_GROUP(test_col_testing_links);

TEST_SETUP(test_col_creating_links)
{
	create_security_data_files();
	ocf_sec_register_ps_handler(&temp_doxm_handler, &temp_pstat_handler, &temp_cred_handler, &temp_acl2_handler);
	ocf_init(OCF_CLIENT_SERVER, "Samsung", OCF_SH_100);

}

TEST_TEAR_DOWN(test_col_creating_links)
{
	ocf_terminate();
	remove_security_data_files();
}

// ADD
TEST(test_col_creating_links, add_link_with_parent_null_return_error)
{

	// Given

	const char *uri_path = RES_LIGHT;

	ocf_resource_s resource_child = ocf_res_new_resource(uri_path);
	ocf_res_set_discoverable(resource_child, true);
	ocf_res_set_interface(resource_child, OIC_IF_BASELINE);
	ocf_res_set_default_interface(resource_child, OIC_IF_BASELINE);
	ocf_res_register_resource(resource_child);

	// When & then
	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, ocf_res_add_link_item(NULL, resource_child));

}

TEST(test_col_creating_links, add_link_with_child_null_return_error)
{

	// Given

	const char *uri_path = RES_ROOM;

	ocf_resource_s resource_parent = ocf_res_new_resource(uri_path);

	ocf_res_set_discoverable(resource_parent, true);
	ocf_res_set_interface(resource_parent, OIC_IF_BASELINE);
	ocf_res_set_interface(resource_parent, OIC_IF_LL);

	// When
	ocf_result_t ret = ocf_res_add_link_item(resource_parent, NULL);
	ocf_res_delete_resource(resource_parent);

	// then
	TEST_ASSERT_EQUAL_INT(OCF_INVALID_PARAM, ret);

}

TEST(test_col_creating_links, add_link_with_child_is_in_return_error)
{

	// Given
	const char *uri_path_child = RES_LIGHT;

	ocf_resource_s resource_child = ocf_res_new_resource(uri_path_child);
	ocf_res_set_discoverable(resource_child, true);
	ocf_res_set_interface(resource_child, OIC_IF_BASELINE);
	ocf_res_set_default_interface(resource_child, OIC_IF_BASELINE);

	const char *uri_path_parent = RES_ROOM;
	ocf_resource_s resource_parent = ocf_res_new_resource(uri_path_parent);

	ocf_res_set_discoverable(resource_parent, true);
	ocf_res_set_interface(resource_parent, OIC_IF_BASELINE);
	ocf_res_set_interface(resource_parent, OIC_IF_LL);

	// When
	ocf_result_t ret = ocf_res_add_link_item(resource_parent, resource_child);

	ocf_res_delete_resource(resource_parent);
	ocf_res_register_resource(resource_child);

	// then
	TEST_ASSERT_NOT_EQUAL(OCF_OK, ret);
}

TEST(test_col_creating_links, add_link_return_ok)
{

	// Given
	const char *uri_path_child = RES_LIGHT;

	ocf_resource_s resource_child = ocf_res_new_resource(uri_path_child);
	ocf_res_set_discoverable(resource_child, true);
	ocf_res_set_interface(resource_child, OIC_IF_BASELINE);
	ocf_res_set_default_interface(resource_child, OIC_IF_BASELINE);
	ocf_res_register_resource(resource_child);

	const char *uri_path_parent = RES_ROOM;
	ocf_resource_s resource_parent = ocf_res_new_resource(uri_path_parent);

	ocf_res_set_discoverable(resource_parent, true);
	ocf_res_set_interface(resource_parent, OIC_IF_BASELINE);
	ocf_res_set_interface(resource_parent, OIC_IF_LL);

	// When
	ocf_result_t ret = ocf_res_add_link_item(resource_parent, resource_child);

	ocf_res_register_resource(resource_parent);

	// then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
}

TEST_GROUP_RUNNER(test_col_creating_links)
{

	// Add
	RUN_TEST_CASE(test_col_creating_links, add_link_with_parent_null_return_error);
	RUN_TEST_CASE(test_col_creating_links, add_link_with_child_null_return_error);
	RUN_TEST_CASE(test_col_creating_links, add_link_with_child_is_in_return_error);
	RUN_TEST_CASE(test_col_creating_links, add_link_return_ok);
}

//-----------------------------------------------

static pthread_cond_t g_condition;
static pthread_mutex_t g_mutex;

static ocf_response_result_t actual_result = OCF_RESPONSE_OK;
static pthread_cond_t g_condition;
static pthread_mutex_t g_mutex;

static void set_endpoint(void)
{

	uint16_t udp_normal_port_v4 = 0;
	rt_get_ports_v4(&udp_normal_port_v4, NULL, NULL, NULL);

	rt_endpoint_set(&g_endpoint, "127.0.0.1", udp_normal_port_v4, OCF_UDP | OCF_IPV4);

}

#define RESOURCE_LEN 3
static void creat_resource(const ocf_interface_mask_t interface_value)
{

	const char *uri_path_array[RESOURCE_LEN] = { RES_LIGHT, RES_FAN, RES_SPEAKER };
	const char *uri_path_link = RES_ROOM;
	int i = 0;

	ocf_resource_s resource_array[RESOURCE_LEN], resource_link;

	for (i = 0; i < RESOURCE_LEN; ++i) {
		resource_array[i] = ocf_res_new_resource(uri_path_array[i]);
		ocf_res_set_discoverable(resource_array[i], true);
		ocf_res_set_observable(resource_array[i], true);
		ocf_res_set_interface(resource_array[i], OIC_IF_BASELINE);
		ocf_res_set_default_interface(resource_array[i], OIC_IF_BASELINE);
		ocf_res_register_resource(resource_array[i]);
	}

	resource_link = ocf_res_new_resource(uri_path_link);
	ocf_res_set_discoverable(resource_link, true);
	ocf_res_set_interface(resource_link, interface_value);
	ocf_res_set_default_interface(resource_link, OIC_IF_BASELINE);

	for (i = 0; i < RESOURCE_LEN - 1; ++i) {
		ocf_res_add_link_item(resource_link, resource_array[i]);
	}

	ocf_res_register_resource(resource_link);
}

TEST_SETUP(test_col_testing_links)
{
	actual_result = OCF_RESPONSE_OK;
	pthread_mutex_init(&g_mutex, NULL);
	pthread_cond_init(&g_condition, NULL);

	create_security_data_files();
	ocf_sec_register_ps_handler(&temp_doxm_handler, &temp_pstat_handler, &temp_cred_handler, &temp_acl2_handler);
	ocf_init(OCF_CLIENT_SERVER, "Samsung", OCF_SH_100);

	creat_resource(OIC_IF_BASELINE | OIC_IF_LL);
	set_endpoint();
}

TEST_TEAR_DOWN(test_col_testing_links)
{
	actual_result = OCF_RESPONSE_OK;
	pthread_cond_destroy(&g_condition);
	pthread_mutex_destroy(&g_mutex);

	ocf_terminate();
	remove_security_data_files();
}

static void respond_get_callback(ocf_rep_decoder_s rep, const ocf_response_result_t response_result)
{

	pthread_mutex_lock(&g_mutex);
	actual_result = response_result;
	pthread_mutex_unlock(&g_mutex);

	if (response_result != OCF_RESPONSE_OK) {
		goto exit;
	}
	// TODO
	// check whether rep has correct value or not

	RT_LOG_BUFFER_I(TAG, rep, 100);

exit:
	pthread_mutex_lock(&g_mutex);
	pthread_cond_signal(&g_condition);
	pthread_mutex_unlock(&g_mutex);

}

TEST(test_col_testing_links, get_link_from_no_colres_return_error)
{

	ocf_result_t ret = OCF_OK;
	ret = ocf_request_get_send(&g_endpoint, RES_LIGHT, "if=oic.if.ll", true, respond_get_callback);

	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);

	wait_for_condition(&g_mutex, &g_condition);
	// wait
	TEST_ASSERT_NOT_EQUAL(OCF_RESPONSE_OK, actual_result);

}

TEST(test_col_testing_links, get_link_from_colres_return_ok)
{

	ocf_result_t ret = OCF_OK;
	ret = ocf_request_get_send(&g_endpoint, RES_ROOM, "if=oic.if.ll", true, respond_get_callback);

	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);

	wait_for_condition(&g_mutex, &g_condition);
	// wait
	TEST_ASSERT_EQUAL_INT(OCF_RESPONSE_OK, actual_result);

}

TEST_GROUP_RUNNER(test_col_testing_links)
{

	RUN_TEST_CASE(test_col_testing_links, get_link_from_no_colres_return_error);
	RUN_TEST_CASE(test_col_testing_links, get_link_from_colres_return_ok);
}

#ifndef CONFIG_IOTIVITY_RT

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_col_creating_links);
	RUN_TEST_GROUP(test_col_testing_links);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
