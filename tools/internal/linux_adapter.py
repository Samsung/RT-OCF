import subprocess
import glob
import os

from config import LINUX_BUILD_DIR
from config import LINUX_LINUX_TEST_DIR
from config import LINUX_LINUX_TEST_BIN_DIR
from config import IOTIVITY_RT_ROOT_TOOLS_INTERNAL


from common import Result
from utils import execute
from utils import execute_return_output
from utils import write_result
from utils import raise_exception_if_exitcode_is_error
from utils import get_test_options


from iotivity_rt_error import IotivityRTError

TEST_SUMMARY_FILE = os.path.join(
    IOTIVITY_RT_ROOT_TOOLS_INTERNAL,
    'test_summary.rb')

BUILD_FAIL_MESSAGE = "Build is Failed T^T"
TEST_FAIL_MESSAGE = "Test is Failed T^T"
COVERAGE_FAIL_MESSAGE = "Calculating coverage is failed T^T"
TESTBINARY_FAIL_MESSAGE = "make testbinary is failed T^T"


class LinuxAdapter:
    def __init__(self):
        pass

    def build(self):
        try:
            self.make()
        except subprocess.CalledProcessError as e:
            raise IotivityRTError(e.returncode, message=BUILD_FAIL_MESSAGE)

    def test(self, verbose=False, group='', name='', repeat=1):
        try:
            options = get_test_options(verbose=verbose, name=name, repeat=repeat)
            return self.execute_test_binary(options=options, target_str=group)
        except subprocess.CalledProcessError as e:
            raise IotivityRTError(e.returncode, message=TEST_FAIL_MESSAGE)

    def coverage_lcov(self):
        result = Result(message='')
        try:
            execute('sh -c "cd {} && lcov -c -d ./ -o {}/lcov.cov"'.format(LINUX_BUILD_DIR, LINUX_BUILD_DIR))
            result = execute_return_output('sh -c "cd {} && \
                lcov -r {}/lcov.cov  \
                \*extlibs/\* \*mocks\* /usr/\* \*/test/\* \*/os/linux/\* \
                --no-external -o {}/filtered-lcov.cov"'.format(LINUX_BUILD_DIR, LINUX_BUILD_DIR, LINUX_BUILD_DIR))
            raise_exception_if_exitcode_is_error(result)
            execute('sh -c "cd {} && genhtml {}/filtered-lcov.cov -o covhtml"'.format(LINUX_BUILD_DIR, LINUX_BUILD_DIR))
            result.message = self.get_coverage_message(result.data)
            return result
        except subprocess.CalledProcessError as e:
            raise IotivityRTError(e.returncode, message=COVERAGE_FAIL_MESSAGE)

    def get_coverage_message(self, output):
        line_coverage = '0%'
        function_coverage = '0%'

        for line in output.split('\n'):
            if 'lines..' in line:
                line_coverage = line.strip().split(' ')[1]
            if 'functions..' in line:
                function_coverage = line.strip().split(' ')[1]
        return 'line: {}, function: {}'.format(
            line_coverage, function_coverage)

    def testbinary(self, with_coverage=False):
        try:
            command = "make testbinary"
            if with_coverage:
                command += ' WITH_COVERAGE=1'
            execute('sh -c "cd {} && {}"'.format(LINUX_BUILD_DIR, command))
        except subprocess.CalledProcessError as e:
            raise IotivityRTError(e.returncode, message=TESTBINARY_FAIL_MESSAGE)

    def execute_test_binary(self, options='', target_str=''):
        execute('rm -rf {}/*.result'.format(LINUX_LINUX_TEST_BIN_DIR))
        for test_bin in self.get_test_binary_list(target_str):
            command = test_bin + ' ' + options
            result = execute_return_output(command)
            # raise_exception_if_exitcode_is_error(result)
            self.write_test_result(test_bin, result.data)
        result = execute_return_output('ruby {}'.format(TEST_SUMMARY_FILE))
        result.message = self.get_total_test_result(result.data)
        return result

    def get_total_test_result(self, output):
        for line in output.split('\n'):
            if 'TOTAL TESTS' in line:
                return line
        return None

    def get_test_binary_list(self, target_str):
        filepath_arr = []
        for filepath in glob.glob(
                '{}/test_*'.format(LINUX_LINUX_TEST_BIN_DIR)):
            if self.is_target_test_binary(filepath, target_str):
                filepath_arr.append(filepath)
        return filepath_arr

    def is_target_test_binary(self, filepath, target_str):
        filename = os.path.basename(filepath)

        if target_str.endswith('.c'):
            target_str = target_str[:-2]

        if filename.endswith('.result'):
            return False
        if target_str is None or target_str == '':
            return True
        if target_str in filename:
            return True
        if target_str.startswith('rt_'):
            return target_str[3:] in filename
        return False

    def write_test_result(self, test_bin_name, data):
        result_name = test_bin_name + '.result'
        subprocess.call('rm -rf {}'.format(result_name), shell=True)
        f = open(result_name, 'w')
        f.write(data)
        f.close()

    def distclean(self):
        execute('sh -c "cd {} && make distclean"'.format(LINUX_BUILD_DIR))

    def make(self):
        execute('sh -c "cd {} && make"'.format(LINUX_BUILD_DIR))


def test_is_target_test_binary():
    adapter = LinuxAdapter()
    result = adapter.get_test_binary_list('test_manager')
    assert 1 == len(result)
    assert result[0].endswith('test_manager')


def test_is_target_test_binary_all():
    adapter = LinuxAdapter()
    result = adapter.get_test_binary_list('')
    assert 1 < len(result)


def test_is_target_test_binary_all():
    adapter = LinuxAdapter()
    result = adapter.get_test_binary_list(None)
    assert 1 < len(result)
