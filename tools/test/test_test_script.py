import os
from subprocess import call

from tools.internal.config import IOTIVITY_RT_ROOT
from tools.internal.config import IOTIVITY_RT_ROOT_TOOLS
from tools.internal.config import CI_LINUX_TEST_FILE_NAME
from tools.internal.config import CI_TIZENRT_TEST_FILE_NAME

from tools.internal.config import CI_LINUX_COVERAGE_FILE_NAME

from tools.test.common import make_fail_file
from tools.test.common import remove_fail_file


class TestTestScript:
    def setup_method(self, method):
        call('rm -rf ci_*.txt', shell=True)

    def teardown_method(self, method):
        call('rm -rf ci_*.txt', shell=True)

    def test_linux_test(self):
        command = '{}/test.py linux'.format(IOTIVITY_RT_ROOT_TOOLS)
        assert 0 == call(command, shell=True)
        assert not os.path.isfile(CI_LINUX_TEST_FILE_NAME)

    def test_linux_test_fail(self):
        try:
            make_fail_file()
            command = '{}/test.py linux --ci'.format(IOTIVITY_RT_ROOT_TOOLS)
            assert 0 != call(command, shell=True)
            assert os.path.isfile(CI_LINUX_TEST_FILE_NAME)
        finally:
            remove_fail_file()

    def test_linux_test_ci(self):
        command = '{}/test.py linux --ci'.format(IOTIVITY_RT_ROOT_TOOLS)
        assert 0 == call(command, shell=True)
        assert os.path.isfile(CI_LINUX_TEST_FILE_NAME)

    def test_linux_test_rebuild(self):
        command = '{}/test.py linux --rebuild'.format(IOTIVITY_RT_ROOT_TOOLS)
        assert 0 == call(command, shell=True)
        assert not os.path.isfile(CI_LINUX_TEST_FILE_NAME)

    def test_linux_test_rebuild_ci(self):
        command = '{}/test.py linux --ci --rebuild'.format(
            IOTIVITY_RT_ROOT_TOOLS)
        assert 0 == call(command, shell=True)
        assert os.path.isfile(CI_LINUX_TEST_FILE_NAME)

    def test_linux_test_coverage(self):
        command = '{}/test.py linux --cov'.format(IOTIVITY_RT_ROOT_TOOLS)
        assert 0 == call(command, shell=True)
        assert not os.path.isfile(CI_LINUX_COVERAGE_FILE_NAME)

    def test_linux_test_coverage_ci(self):
        command = '{}/test.py linux --ci --cov'.format(IOTIVITY_RT_ROOT_TOOLS)
        assert 0 == call(command, shell=True)
        assert os.path.isfile(CI_LINUX_COVERAGE_FILE_NAME)

    def test_linux_test_coverage_failed(self):
        try:
            make_fail_file()
            command = '{}/test.py linux --cov'.format(IOTIVITY_RT_ROOT_TOOLS)
            assert 0 != call(command, shell=True)
            assert not os.path.isfile(CI_LINUX_COVERAGE_FILE_NAME)
        finally:
            remove_fail_file()

    def test_tizenrt_test(self):
        command = '{}/test.py tizenrt'.format(IOTIVITY_RT_ROOT_TOOLS)
        assert 0 == call(command, shell=True)
        assert not os.path.isfile(CI_TIZENRT_TEST_FILE_NAME)

    def test_tizenrt_test_fail(self):
        try:
            make_fail_file()
            command = '{}/test.py tizenrt'.format(IOTIVITY_RT_ROOT_TOOLS)
            assert 0 != call(command, shell=True)
            assert not os.path.isfile(CI_TIZENRT_TEST_FILE_NAME)
        finally:
            remove_fail_file()

    def test_tizenrt_test_ci(self):
        command = '{}/test.py tizenrt --ci'.format(IOTIVITY_RT_ROOT_TOOLS)
        assert 0 == call(command, shell=True)
        assert os.path.isfile(CI_TIZENRT_TEST_FILE_NAME)

    def test_tizenrt_test_rebuild(self):
        command = '{}/test.py tizenrt --rebuild'.format(IOTIVITY_RT_ROOT_TOOLS)
        assert 0 == call(command, shell=True)
        assert not os.path.isfile(CI_TIZENRT_TEST_FILE_NAME)
