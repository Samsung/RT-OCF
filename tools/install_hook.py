#!/usr/bin/env python

import os
from internal.config import IOTIVITY_RT_ROOT
from internal.config import IOTIVITY_RT_HOOK_PATH

from internal.utils import execute
from internal.utils import print_warning

GIT_HOOK_PATH = os.path.join(IOTIVITY_RT_ROOT, '.git', 'hooks')


def run():
    print_warning('Copy pre-commit..')
    execute(
        'cp {}/pre-commit {}/pre-commit'.format(IOTIVITY_RT_HOOK_PATH, GIT_HOOK_PATH))
    print_warning('Copy pre-commit end..')


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(
        description='Install git hook into .git/hooks')
    args = parser.parse_args()
    run()
