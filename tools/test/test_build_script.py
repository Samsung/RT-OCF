import os
from subprocess import call

from tools.internal.config import RT_OCF_ROOT
from tools.internal.config import RT_OCF_ROOT_TOOLS
from tools.internal.config import CI_LINUX_BUILD_FILE_NAME
from tools.internal.config import CI_TIZENRT_BUILD_FILE_NAME

from tools.test.common import make_fail_file
from tools.test.common import remove_fail_file


class TestBuildScript:
    def setup_method(self, method):
        call('rm -rf ci_*.txt', shell=True)

    def teardown_method(self, method):
        call('rm -rf ci_*.txt', shell=True)

    def test_linux_build(self):
        command = '{}/build.py linux'.format(RT_OCF_ROOT_TOOLS)
        assert 0 == call(command, shell=True)
        assert not os.path.isfile(CI_LINUX_BUILD_FILE_NAME)

    def test_linux_build_fail(self):
        try:
            make_fail_file()
            command = '{}/build.py linux --ci'.format(RT_OCF_ROOT_TOOLS)
            assert 0 != call(command, shell=True)
            assert os.path.isfile(CI_LINUX_BUILD_FILE_NAME)
        finally:
            remove_fail_file()

    def test_linux_build_ci(self):
        command = '{}/build.py linux --ci'.format(RT_OCF_ROOT_TOOLS)
        assert 0 == call(command, shell=True)
        assert os.path.isfile(CI_LINUX_BUILD_FILE_NAME)

    def test_linux_build_rebuild(self):
        command = '{}/build.py linux --rebuild'.format(RT_OCF_ROOT_TOOLS)
        assert 0 == call(command, shell=True)
        assert not os.path.isfile(CI_LINUX_BUILD_FILE_NAME)

    def test_linux_build_rebuild_ci(self):
        command = '{}/build.py linux --ci --rebuild'.format(
            RT_OCF_ROOT_TOOLS)
        assert 0 == call(command, shell=True)
        assert os.path.isfile(CI_LINUX_BUILD_FILE_NAME)

    def test_tizenrt_build(self):
        command = '{}/build.py tizenrt'.format(RT_OCF_ROOT_TOOLS)
        assert 0 == call(command, shell=True)
        assert not os.path.isfile(CI_TIZENRT_BUILD_FILE_NAME)

    def test_tizenrt_build_fail(self):
        try:
            make_fail_file()
            command = '{}/build.py tizenrt --ci'.format(RT_OCF_ROOT_TOOLS)
            assert 0 != call(command, shell=True)
            assert os.path.isfile(CI_TIZENRT_BUILD_FILE_NAME)
        finally:
            remove_fail_file()

    def test_tizenrt_build_ci(self):
        command = '{}/build.py tizenrt --ci'.format(RT_OCF_ROOT_TOOLS)
        assert 0 == call(command, shell=True)
        assert os.path.isfile(CI_TIZENRT_BUILD_FILE_NAME)

    def test_tizenrt_build_rebuild(self):
        command = '{}/build.py tizenrt --rebuild'.format(
            RT_OCF_ROOT_TOOLS)
        assert 0 == call(command, shell=True)
        assert not os.path.isfile(CI_TIZENRT_BUILD_FILE_NAME)

    def test_tizenrt_build_rebuild_ci(self):
        command = '{}/build.py tizenrt --ci --rebuild'.format(
            RT_OCF_ROOT_TOOLS)
        assert 0 == call(command, shell=True)
        assert os.path.isfile(CI_TIZENRT_BUILD_FILE_NAME)
