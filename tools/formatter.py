#!/usr/bin/env python

import sys
import os

from internal.config import IOTIVITY_RT_ROOT
from internal.config import IOTIVITY_RT_ROOT_TOOLS

from internal.utils import write_result
from internal.utils import execute
from internal.utils import find_iotivity_rt_source_files
from subprocess import call

FORMATTER_PATH = os.path.join(IOTIVITY_RT_ROOT_TOOLS, 'formatter.sh')


def format(file_list):
    for file in file_list:
        call('{} {}'.format(FORMATTER_PATH, file), shell=True)
        # execute('{} {}'.format(FORMATTER_PATH, file))


def run(targets, is_all):
    if is_all:
        targets = []
        targets.append(IOTIVITY_RT_ROOT)
    file_list = find_iotivity_rt_source_files(targets)

    format(file_list)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument('targets', metavar='Target', nargs='*',
                        help='Directory or files to execute formatter')
    parser.add_argument(
        "--all",
        dest="all",
        required=False,
        action='store_true',
        help="True, if you want to format all of source code in iotivity-rt.")
    args = parser.parse_args()
    run(args.targets, is_all=args.all)
