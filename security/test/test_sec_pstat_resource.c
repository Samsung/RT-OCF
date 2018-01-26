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
#include "rt_sec_pstat_resource.h"
#include "rt_list.h"
#include "rt_mem.h"
#include "rt_sec_persistent_storage.h"

#define TAG "TEST_PSTAT_RES"

#ifdef CONFIG_ENABLE_RT_OCF
static char PSTAT_FILE[] = "/mnt/svr_pstat.dat";
static char PSTAT_NO_FILE[] = "/mnt/svr_no_pstat.dat";
#else
static char PSTAT_FILE[] = "svr_pstat.dat";
static char PSTAT_NO_FILE[] = "svr_no_pstat.dat";
#endif

static uint8_t pstat_data[] = {
	0xBF, 0x63, 0x64, 0x6F, 0x73, 0xA2, 0x61, 0x73, 0x01, 0x61, 0x70, 0xF4, 0x64, 0x69, 0x73, 0x6F,
	0x70, 0xF4, 0x62, 0x63, 0x6D, 0x02, 0x62, 0x74, 0x6D, 0x00, 0x62, 0x6F, 0x6D, 0x04, 0x62, 0x73,
	0x6D, 0x04, 0x6A, 0x72, 0x6F, 0x77, 0x6E, 0x65, 0x72, 0x75, 0x75, 0x69, 0x64, 0x78, 0x24, 0x31,
	0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x2D, 0x31, 0x31, 0x31, 0x31, 0x2D, 0x31, 0x31, 0x31,
	0x31, 0x2D, 0x31, 0x31, 0x31, 0x31, 0x2D, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31, 0x31,
	0x31, 0x31, 0x31, 0xFF
};

FILE *pstat_fopen(const char *path, const char *mode)
{
	(void)path;
	return fopen(PSTAT_FILE, mode);
}

FILE *pstat_no_fopen(const char *path, const char *mode)
{
	(void)path;
	return fopen(PSTAT_NO_FILE, mode);
}

static rt_persistent_storage_handler_s ps_doxm = { pstat_fopen, fread, fwrite, fclose };
static rt_persistent_storage_handler_s ps_pstat = { pstat_fopen, fread, fwrite, fclose };
static rt_persistent_storage_handler_s ps_cred = { pstat_fopen, fread, fwrite, fclose };
static rt_persistent_storage_handler_s ps_acl2 = { pstat_fopen, fread, fwrite, fclose };

TEST_GROUP(test_sec_pstat_resource);

TEST_SETUP(test_sec_pstat_resource)
{
	int fd;
	if (0 < (fd = open(PSTAT_FILE, O_WRONLY | O_CREAT, 0644))) {
		write(fd, pstat_data, sizeof(pstat_data));
		close(fd);
	}
	rt_sec_register_ps_handler(&ps_doxm, &ps_pstat, &ps_cred, &ps_acl2);
	rt_mem_pool_init();
	rt_random_init();
	rt_resource_manager_init("Samsung", "1.0");

}

TEST_TEAR_DOWN(test_sec_pstat_resource)
{
	rt_resource_manager_terminate();
	rt_mem_pool_terminate();
}

TEST(test_sec_pstat_resource, rt_sec_pstat_init)
{
	// Given
	
	// When
	ocf_result_t ret = rt_sec_pstat_init();

	// Then
	TEST_ASSERT_EQUAL_INT(OCF_OK, ret);
	
	rt_sec_pstat_terminate();
}

TEST(test_sec_pstat_resource, rt_convert_pstat_to_payload)
{
	// Given
	rt_sec_pstat_init();

	rt_rep_decoder_s *decoder = rt_rep_decoder_init(pstat_data, sizeof(pstat_data));
	rt_sec_pstat_s pstat;
	rt_convert_payload_to_pstat(decoder, &pstat, false);
	rt_rep_decoder_release(decoder);

	// When
	rt_rep_encoder_s *rep = rt_convert_pstat_to_payload(&pstat, false);

	// Then
	TEST_ASSERT_EQUAL_INT(sizeof(pstat_data), rep->payload_size);

	rt_rep_encoder_release(rep);

	rt_sec_pstat_terminate();
}

TEST_GROUP_RUNNER(test_sec_pstat_resource)
{
	RUN_TEST_CASE(test_sec_pstat_resource, rt_sec_pstat_init);
	RUN_TEST_CASE(test_sec_pstat_resource, rt_convert_pstat_to_payload);
}

#ifndef CONFIG_ENABLE_RT_OCF

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_sec_pstat_resource);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
