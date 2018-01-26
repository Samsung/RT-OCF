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

#include <fcntl.h>
#include "unity.h"
#include "unity_fixture.h"
#include "ocf_types.h"
#include "rt_logger.h"
#include "rt_rep.h"
#include "rt_uuid.h"
#include "rt_sec_doxm_resource.h"
#include "rt_sec_persistent_storage.h"
#include "rt_mem.h"

#define TAG "TC_SEC_DOXM"

#ifdef CONFIG_ENABLE_RT_OCF
static const char DOXM_TC_DOXM_PS_PATH[] = "/mnt/test_svr_doxm.dat";
#else
static char DOXM_TC_DOXM_PS_PATH[] = "test_svr_doxm.dat";
#endif

static const char TEMP_DOXM_DI_NULL_DATA[] = {
	0xa7, 0x64, 0x6f, 0x78, 0x6d, 0x73, 0x81, 0x1b, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x66, 0x6f, 0x78, 0x6d, 0x73, 0x65, 0x6c, 0x1b,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x63, 0x73, 0x63, 0x74,
	0x1b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x65, 0x6f, 0x77,
	0x6e, 0x65, 0x64, 0xf5, 0x6a, 0x64, 0x65, 0x76, 0x69, 0x63, 0x65, 0x75,
	0x75, 0x69, 0x64, 0x60, 0x6c, 0x64, 0x65, 0x76, 0x6f, 0x77, 0x6e, 0x65,
	0x72, 0x75, 0x75, 0x69, 0x64, 0x60, 0x6a, 0x72, 0x6f, 0x77, 0x6e, 0x65,
	0x72, 0x75, 0x75, 0x69, 0x64, 0x78, 0x24, 0x36, 0x31, 0x36, 0x34, 0x36,
	0x64, 0x36, 0x39, 0x2d, 0x36, 0x65, 0x34, 0x34, 0x2d, 0x36, 0x35, 0x37,
	0x36, 0x2d, 0x36, 0x39, 0x36, 0x33, 0x2d, 0x36, 0x35, 0x35, 0x35, 0x37,
	0x35, 0x36, 0x39, 0x36, 0x34, 0x33, 0x30
};

static const char TEMP_DOXM_DI_DATA[] = {
	0xBF, 0x64, 0x6F, 0x78, 0x6D, 0x73, 0x81, 0x00, 0x66, 0x6F, 0x78, 0x6D, 0x73, 0x65, 0x6C, 0x00,
	0x63, 0x73, 0x63, 0x74, 0x01, 0x65, 0x6F, 0x77, 0x6E, 0x65, 0x64, 0xF5, 0x6A, 0x64, 0x65, 0x76,
	0x69, 0x63, 0x65, 0x75, 0x75, 0x69, 0x64, 0x78, 0x24, 0x36, 0x31, 0x36, 0x34, 0x36, 0x64, 0x36,
	0x39, 0x2D, 0x36, 0x65, 0x34, 0x34, 0x2D, 0x36, 0x35, 0x37, 0x36, 0x2D, 0x36, 0x39, 0x36, 0x33,
	0x2D, 0x36, 0x35, 0x35, 0x35, 0x37, 0x35, 0x36, 0x39, 0x36, 0x34, 0x33, 0x30, 0x6C, 0x64, 0x65,
	0x76, 0x6F, 0x77, 0x6E, 0x65, 0x72, 0x75, 0x75, 0x69, 0x64, 0x78, 0x24, 0x36, 0x31, 0x36, 0x34,
	0x36, 0x64, 0x36, 0x39, 0x2D, 0x36, 0x65, 0x34, 0x34, 0x2D, 0x36, 0x35, 0x37, 0x36, 0x2D, 0x36,
	0x39, 0x36, 0x33, 0x2D, 0x36, 0x35, 0x35, 0x35, 0x37, 0x35, 0x36, 0x39, 0x36, 0x34, 0x33, 0x30,
	0x6A, 0x72, 0x6F, 0x77, 0x6E, 0x65, 0x72, 0x75, 0x75, 0x69, 0x64, 0x78, 0x24, 0x36, 0x31, 0x36,
	0x34, 0x36, 0x64, 0x36, 0x39, 0x2D, 0x36, 0x65, 0x34, 0x34, 0x2D, 0x36, 0x35, 0x37, 0x36, 0x2D,
	0x36, 0x39, 0x36, 0x33, 0x2D, 0x36, 0x35, 0x35, 0x35, 0x37, 0x35, 0x36, 0x39, 0x36, 0x34, 0x33,
	0x30, 0xFF
};

static FILE *test_doxm_fopen(const char *path, const char *mode)
{
	(void)path;
	return fopen(DOXM_TC_DOXM_PS_PATH, mode);
}

static rt_persistent_storage_handler_s DOXM_TC_DOXM_PSH = { test_doxm_fopen, fread, fwrite, fclose };
static rt_persistent_storage_handler_s DOXM_TC_PSTAT_PSH = { test_doxm_fopen, fread, fwrite, fclose };
static rt_persistent_storage_handler_s DOXM_TC_CRED_PSH = { test_doxm_fopen, fread, fwrite, fclose };
static rt_persistent_storage_handler_s DOXM_TC_ACL2_PSH = { test_doxm_fopen, fread, fwrite, fclose };

static const char doxm_deviceuuid[RT_UUID_STR_LEN] = "61646d69-6e44-6576-6963-655575696430";

TEST_GROUP(test_sec_doxm_resource);

TEST_SETUP(test_sec_doxm_resource)
{
	rt_mem_pool_init();
	rt_random_init();
	rt_resource_manager_init("Samsung", "1.0");
}

TEST_TEAR_DOWN(test_sec_doxm_resource)
{
	rt_sec_doxm_terminate();
	rt_resource_manager_terminate();
	rt_mem_pool_terminate();
}

TEST(test_sec_doxm_resource, rt_sec_doxm_get_deviceuuid)
{
	// When
	int fd;
	if (0 < (fd = open(DOXM_TC_DOXM_PS_PATH, O_WRONLY | O_CREAT, 0644))) {
		write(fd, TEMP_DOXM_DI_NULL_DATA, sizeof(TEMP_DOXM_DI_NULL_DATA));
		close(fd);
	}
	rt_sec_register_ps_handler(&DOXM_TC_DOXM_PSH, &DOXM_TC_PSTAT_PSH, &DOXM_TC_CRED_PSH, &DOXM_TC_ACL2_PSH);
	rt_sec_doxm_init();
	char actual_deviceuuid[RT_UUID_STR_LEN];
	ocf_result_t ret = rt_sec_doxm_get_deviceuuid(actual_deviceuuid);

	// Then
	rt_uuid_t expect_uuid;
	char expect_deviceuuid[RT_UUID_STR_LEN];
	rt_uuid_generate(expect_uuid);
	rt_uuid_uuid2str(expect_uuid, expect_deviceuuid, RT_UUID_STR_LEN);
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_STRING(expect_deviceuuid, actual_deviceuuid);
}

TEST(test_sec_doxm_resource, rt_sec_doxm_get_deviceuuid_with_ps)
{
	// Given
	int fd;
	if (0 < (fd = open(DOXM_TC_DOXM_PS_PATH, O_WRONLY | O_CREAT, 0644))) {
		write(fd, TEMP_DOXM_DI_DATA, sizeof(TEMP_DOXM_DI_DATA));
		close(fd);
	}
	rt_sec_register_ps_handler(&DOXM_TC_DOXM_PSH, &DOXM_TC_PSTAT_PSH, &DOXM_TC_CRED_PSH, &DOXM_TC_ACL2_PSH);
	rt_sec_doxm_init();

	// When
	char actual_deviceuuid[RT_UUID_STR_LEN];
	ocf_result_t ret = rt_sec_doxm_get_deviceuuid(actual_deviceuuid);

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	TEST_ASSERT_EQUAL_STRING(doxm_deviceuuid, actual_deviceuuid);
}

TEST(test_sec_doxm_resource, rt_convert_doxm_to_payload)
{
	// Given
	int fd;
	if (0 < (fd = open(DOXM_TC_DOXM_PS_PATH, O_WRONLY | O_CREAT, 0644))) {
		write(fd, TEMP_DOXM_DI_DATA, sizeof(TEMP_DOXM_DI_DATA));
		close(fd);
	}
	rt_sec_register_ps_handler(&DOXM_TC_DOXM_PSH, &DOXM_TC_PSTAT_PSH, &DOXM_TC_CRED_PSH, &DOXM_TC_ACL2_PSH);
	rt_sec_doxm_init();

	// When
	rt_rep_encoder_s *rep = rt_convert_doxm_to_payload(NULL, false);

	RT_LOG_BUFFER_D(TAG, rep->payload, rep->payload_size);

	// Then
	TEST_ASSERT_EQUAL_INT(sizeof(TEMP_DOXM_DI_DATA), rep->payload_size);

	rt_rep_encoder_release(rep);
}

TEST_GROUP_RUNNER(test_sec_doxm_resource)
{
	RUN_TEST_CASE(test_sec_doxm_resource, rt_sec_doxm_get_deviceuuid);
	RUN_TEST_CASE(test_sec_doxm_resource, rt_sec_doxm_get_deviceuuid_with_ps);
	RUN_TEST_CASE(test_sec_doxm_resource, rt_convert_doxm_to_payload);
}

#ifndef CONFIG_ENABLE_RT_OCF

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_sec_doxm_resource);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
