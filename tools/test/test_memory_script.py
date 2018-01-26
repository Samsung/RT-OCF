import os
from subprocess import call

from tools.internal.config import RT_OCF_ROOT
from tools.internal.config import RT_OCF_ROOT_TOOLS
from tools.internal.config import CI_LINUX_LEAK_FILE_NAME
from tools.internal.config import CI_LINUX_PEAK_FILE_NAME

from tools.test.common import make_fail_file
from tools.test.common import remove_fail_file


class TestMemoryScript:
    def setup_method(self, method):
        call('rm -rf ci_*.txt', shell=True)

    def teardown_method(self, method):
        call('rm -rf ci_*.txt', shell=True)

    def test_memory_leak(self):
        command = '{}/memory.py leak'.format(RT_OCF_ROOT_TOOLS)
        call(command, shell=True)
        assert not os.path.isfile(CI_LINUX_LEAK_FILE_NAME)

    def test_memory_leak_ci(self):
        command = '{}/memory.py leak --ci'.format(RT_OCF_ROOT_TOOLS)
        call(command, shell=True)
        assert os.path.isfile(CI_LINUX_LEAK_FILE_NAME)

    def test_memory_peak(self):
        command = '{}/memory.py peak'.format(RT_OCF_ROOT_TOOLS)
        call(command, shell=True)
        assert not os.path.isfile(CI_LINUX_PEAK_FILE_NAME)

    def test_memory_peak_ci(self):
        command = '{}/memory.py peak --ci'.format(RT_OCF_ROOT_TOOLS)
        call(command, shell=True)
        assert os.path.isfile(CI_LINUX_PEAK_FILE_NAME)
