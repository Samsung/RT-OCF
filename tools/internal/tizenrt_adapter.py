import subprocess

from internal.config import TIZEN_RT_ROOT
from internal.config import TIZEN_RT_OS_DIR
from internal.config import TIZEN_RT_TOOLS_DIR
from internal.config import TIZEN_RT_BUILD_DIR

from internal.tizen_rt_test_generator import TizenRTTestGenerator

from internal.common import Result
from internal.utils import execute
from internal.utils import execute_return_output
from internal.utils import raise_exception_if_exitcode_is_error
from internal.utils import get_test_options

from internal.tizenrt_testresult_collector import TestResultCollector
from internal.iotivity_rt_error import IotivityRTError

# OPENOCD_PATH = '{}/build/configs/artik053/tools/openocd'.format(TIZEN_RT_ROOT)

# FLASH_ALL_COMMAND = 'sh -c "cd {} && ./linux64/openocd -f artik053.cfg -c \'\
#                 init; \
#                 reset init; \
#                 flash_write bl1    ../../bin/bl1.bin;      \
#                 flash_write bl2    ../../bin/bl2.bin;      \
#                 flash_write sssfw  ../../bin/sssfw.bin;    \
#                 flash_write wlanfw ../../bin/wlanfw.bin;   \
#                 flash_write os     ../../../../output/bin/tinyara_head.bin; \
#                 reset; \
#                 exit\'"'.format(OPENOCD_PATH)
# FLASH_COMMAND = 'sh -c "cd {} && \
#                 ./linux64/openocd -f artik053.cfg -c \'\
#                 init; \
#                 reset init; \
#                 flash_write os ../../../../output/bin/tinyara_head.bin; \
#                 reset; \
#                 exit\'"'.format(OPENOCD_PATH)

FLASH_ALL_COMMAND = 'sh -c "cd {}/os && make download ERASE_USERFS && make download ALL && make download RESET"'.format(TIZEN_RT_ROOT)
FLASH_COMMAND = 'sh -c "cd {}/os && make download ERASE_USERFS &&  make download OS && make download RESET"'.format(TIZEN_RT_ROOT)

BUILD_FAIL_MESSAGE = "Build is Failed T^T"
TEST_FAIL_MESSAGE = "Test is Failed T^T"


class TizenRTAdapter:
    def __init__(self, config):
        self.config = config

    def build(self):
        try:
            self.generate_testcase_runner_and_makedefs()
            execute('sh -c "cd {} && make"'.format(TIZEN_RT_OS_DIR))
        except subprocess.CalledProcessError as e:
            raise IotivityRTError(e.returncode, BUILD_FAIL_MESSAGE)

    def test(self, verbose=False, group='', name='', repeat=1, is_flash_all=False):
        try:
            self.generate_testcase_runner_and_makedefs()
            self.flash_binary(is_flash_all)
            options = get_test_options(
                verbose=verbose, name=name, repeat=repeat, group=group)
            return self.collect_test_result(options)
        except subprocess.CalledProcessError as e:
            raise IotivityRTError(e.returncode, TEST_FAIL_MESSAGE)

    def copy_tizenrt_test_config(self):
        print('Copy TizenRT config file to execute unittest..')
        execute('cp {}/unittest_config {}/.config'.format(TIZEN_RT_BUILD_DIR, TIZEN_RT_OS_DIR))

    def flash_binary(self, is_flash_all=False):
        if is_flash_all:
            execute(FLASH_ALL_COMMAND)
        else:
            execute(FLASH_COMMAND)

    def collect_test_result(self, options):
        return TestResultCollector().collect(options)

    def distclean(self):
        execute('sh -c "cd {} && make distclean"'.format(TIZEN_RT_OS_DIR))

    def reconfig(self):
        execute(
            'sh -c "cd {} && ./configure.sh {}"'.format(TIZEN_RT_TOOLS_DIR, self.config))

    def generate_testcase_runner_and_makedefs(self):
        print('Generate testcase runner and Makedefs for TizenRT')
        TizenRTTestGenerator().generate()
