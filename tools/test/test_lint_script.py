import os
from subprocess import call

from tools.internal.config import IOTIVITY_RT_ROOT
from tools.internal.config import IOTIVITY_RT_ROOT_TOOLS
from tools.internal.config import CI_LINT_FILE_NAME


class TestLintScript:
    def setup_method(self, method):
        call('rm -rf ci_*.txt', shell=True)

    def teardown_method(self, method):
        call('rm -rf ci_*.txt', shell=True)

    def test_lint(self):
        command = '{}/lint.py'.format(IOTIVITY_RT_ROOT_TOOLS)
        call(command, shell=True)
        assert not os.path.isfile(CI_LINT_FILE_NAME)

    def test_lint_ci(self):
        command = '{}/lint.py --ci'.format(IOTIVITY_RT_ROOT_TOOLS)
        call(command, shell=True)
        assert os.path.isfile(CI_LINT_FILE_NAME)
