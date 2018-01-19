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
	RUN_TEST_GROUP(test_col_creating_links);
	RUN_TEST_GROUP(test_core_device);
	RUN_TEST_GROUP(test_core_introspection);
	RUN_TEST_GROUP(test_core_platform_with_ocf_init);
	RUN_TEST_GROUP(test_core_resource_with_ocf_init);
	RUN_TEST_GROUP(test_observe);
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