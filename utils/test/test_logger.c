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
#include "rt_logger.h"
#include "rt_mem.h"

TEST_GROUP(test_logger);

TEST_SETUP(test_logger)
{
}

TEST_TEAR_DOWN(test_logger)
{
}

TEST(test_logger, test_log)
{
	ocf_log_level_t level;

	for (level = OCF_LOG_DEBUG; level <= OCF_LOG_FATAL; ++level) {
		RT_LOG(level, "Logger", "TEST %d", (int)level);
	}
}

TEST(test_logger, test_log_buffer)
{
	ocf_log_level_t level;
	const char *buf = "01234567890123456789012345678901234567890123456789";
	const int buflen = 50;

	for (level = OCF_LOG_DEBUG; level <= OCF_LOG_FATAL; ++level) {
		RT_LOG_BUFFER(level, "buffer", buf, buflen);
	}
}

TEST(test_logger, test_log_buffer_null)
{
	ocf_log_level_t level;
	const char *buf = NULL;
	const int buflen = 50;

	for (level = OCF_LOG_DEBUG; level <= OCF_LOG_FATAL; ++level) {
		RT_LOG_BUFFER(level, "buffer", buf, buflen);
	}
}

TEST(test_logger, test_log_buffer_size_zero)
{
	ocf_log_level_t level;
	const char buf[2];
	const int buflen = 0;

	for (level = OCF_LOG_DEBUG; level <= OCF_LOG_FATAL; ++level) {
		RT_LOG_BUFFER(level, "buffer", buf, buflen);
	}
}

TEST(test_logger, test_log_buffer_size_negative_value)
{
	ocf_log_level_t level;
	const char buf[2];
	const int buflen = -1;

	for (level = OCF_LOG_DEBUG; level <= OCF_LOG_FATAL; ++level) {
		RT_LOG_BUFFER(level, "buffer", buf, buflen);
	}

}

TEST(test_logger, test_log_buffer_size_huge_value)
{
	ocf_log_level_t level;
	const char buf[2];
	const int buflen = OCF_RT_MEM_POOL_SIZE + 1;

	for (level = OCF_LOG_DEBUG; level <= OCF_LOG_FATAL; ++level) {
		RT_LOG_BUFFER(level, "buffer", buf, buflen);
	}

}

TEST(test_logger, test_log_each_case)
{
	RT_LOG_D("Logger", "TEST Each Case");
	RT_LOG_I("Logger", "TEST Each Case");
	RT_LOG_W("Logger", "TEST Each Case");
	RT_LOG_E("Logger", "TEST Each Case");
	RT_LOG_F("Logger", "TEST Each Case");
}

TEST(test_logger, test_log_buffer_each_case)
{

	const char *buf = "01234567890123456789012345678901234567890123456789";
	const int buflen = 50;

	RT_LOG_BUFFER_D("Logger", buf, buflen);
	RT_LOG_BUFFER_I("Logger", buf, buflen);
	RT_LOG_BUFFER_W("Logger", buf, buflen);
	RT_LOG_BUFFER_E("Logger", buf, buflen);
	RT_LOG_BUFFER_F("Logger", buf, buflen);
}

TEST_GROUP_RUNNER(test_logger)
{
	RUN_TEST_CASE(test_logger, test_log);
	RUN_TEST_CASE(test_logger, test_log_buffer);
	RUN_TEST_CASE(test_logger, test_log_buffer_null);
	RUN_TEST_CASE(test_logger, test_log_buffer_size_zero);
	RUN_TEST_CASE(test_logger, test_log_buffer_size_negative_value);
	RUN_TEST_CASE(test_logger, test_log_buffer_size_huge_value);
	RUN_TEST_CASE(test_logger, test_log_each_case);
	RUN_TEST_CASE(test_logger, test_log_buffer_each_case);
}

#ifndef CONFIG_IOTIVITY_RT

static void RunAllTests(void)
{
	RUN_TEST_GROUP(test_logger);
}

int main(int argc, const char *argv[])
{
	return UnityMain(argc, argv, RunAllTests);
}

#endif
