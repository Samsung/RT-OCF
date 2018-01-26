#!/usr/bin/env python
import subprocess
import os
import sys


from internal.common import Result
from internal.utils import write_result

from internal.linux_adapter import LinuxAdapter
from internal.tizenrt_adapter import TizenRTAdapter
from internal.RT_OCF_error import RT_OCFError

from internal.config import LINUX_BUILD_DIR

from internal.config import CI_LINUX_TEST_FILE_NAME
from internal.config import CI_TIZENRT_TEST_FILE_NAME

from internal.config import CI_LINUX_COVERAGE_FILE_NAME


def exist_gcov_data_in_linux():
    import glob
    if len(glob.glob('{}/*.gcno'.format(LINUX_BUILD_DIR))) > 0:
        return True
    if len(glob.glob('{}/*.gcda'.format(LINUX_BUILD_DIR))) > 0:
        return True
    return False


def test_linux(args):
    adapter = LinuxAdapter()
    test_result = Result(message='')
    coverage_result = Result(message='')
    try:
        if args.rebuild or exist_gcov_data_in_linux() or args.coverage:
            adapter.distclean()
        if not args.skip_build:
            adapter.testbinary(with_coverage=args.coverage)

        if '/' in args.group or '\\' in args.group:
            args.group = os.path.basename(args.group)

        test_result = LinuxAdapter().test(
            verbose=args.verbose,
            group=args.group,
            name=args.name,
            repeat=args.repeat)

        if args.coverage:
            coverage_result = LinuxAdapter().coverage_lcov()

    except RT_OCFError as e:
        test_result = Result(exitcode=e.exitcode, message=e.message)
        coverage_result = Result(exitcode=e.exitcode, message=e.message)
    finally:
        if args.is_ci:
            write_result(CI_LINUX_TEST_FILE_NAME, test_result.message)
            if args.coverage:
                write_result(CI_LINUX_COVERAGE_FILE_NAME, coverage_result.message)
    return test_result


def test_tizenrt(args):
    result = Result(message='')
    try:
        adapter = TizenRTAdapter(config='artik053/zeroroot_unittest')
        if args.rebuild:
            adapter.reconfig()
            adapter.distclean()
            adapter.reconfig()
        print('!!!' + args.group)
        if not args.skip_build:
            adapter.build()
        if '/' in args.group or '\\' in args.group:
            args.group = os.path.basename(args.group)
        result = adapter.test(
            verbose=args.verbose,
            group=args.group,
            name=args.name,
            repeat=args.repeat)
    except RT_OCFError as e:
        result = Result(exitcode=e.exitcode, message=e.message)
    finally:
        if args.is_ci:
            write_result(CI_TIZENRT_TEST_FILE_NAME, result.message)
    return result


def run(args):
    if args.rebuild and args.skip_build:
        print("You must choose between --rebuild and --skip-build")
        exit(1)

    if args.platform == 'linux':
        result = test_linux(args)
    elif args.platform == 'tizenrt':
        result = test_tizenrt(args)
    print(result.message)
    exit(result.exitcode)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()

    subparsers = parser.add_subparsers(
        dest='platform',
        help='Please select a linux or tizenrt.')

    parser_linux = subparsers.add_parser(
        'linux',
        description='Linux Test',
        help='Test iotivity-rt project in linux environment.')
    parser_linux.add_argument(
        '--rebuild',
        dest="rebuild",
        required=False,
        action='store_true',
        help="True, Build after clean")
    parser_linux.add_argument(
        '--skip-build',
        dest="skip_build",
        required=False,
        action='store_true',
        help="True, if you want to execute only test")
    parser_linux.add_argument(
        '--cov',
        dest="coverage",
        required=False,
        action='store_true',
        help="True, If you want to calculate test coverage.")
    parser_linux.add_argument(
        "--ci",
        dest="is_ci",
        required=False,
        action='store_true',
        help="True, if it is ci build.")
    parser_linux.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        default=True,
        help="Print test name before each test run",
        action='store_true')
    parser_linux.add_argument(
        "-g",
        "--group",
        dest="group",
        default='',
        help="Select a test group whose name contains the specified string",
        metavar="GROUP")
    parser_linux.add_argument(
        "-n",
        "--name",
        dest="name",
        default='',
        help="Select a test case whose name contains the specified string",
        metavar="NAME")
    parser_linux.add_argument(
        "-r",
        "--repeat",
        dest="repeat",
        default=1,
        type=int,
        help="Repeat the test for the specified number of times",
        metavar="REPEAT")

    parser_tizenrt = subparsers.add_parser(
        'tizenrt',
        description='Tizen RT Test',
        help='Test iotivity-rt project with TizenRT.')
    parser_tizenrt.add_argument(
        '--skip-build',
        dest="skip_build",
        required=False,
        action='store_true',
        help="True, if you want to execute only test")
    parser_tizenrt.add_argument(
        "--rebuild",
        dest="rebuild",
        required=False,
        action='store_true',
        help="True, Build after clean")
    parser_tizenrt.add_argument(
        "--ci",
        dest="is_ci",
        required=False,
        action='store_true',
        help="True, if it is ci build.")
    parser_tizenrt.add_argument(
        "-v",
        "--verbose",
        dest="verbose",
        default=True,
        help="Print test name before each test run",
        action='store_true')
    parser_tizenrt.add_argument(
        "-g",
        "--group",
        dest="group",
        default='',
        help="Select a test group whose name contains the specified string",
        metavar="GROUP")
    parser_tizenrt.add_argument(
        "-n",
        "--name",
        dest="name",
        default='',
        help="Select a test case whose name contains the specified string",
        metavar="NAME")
    parser_tizenrt.add_argument(
        "-r",
        "--repeat",
        dest="repeat",
        default=1,
        type=int,
        help="Repeat the test for the specified number of times",
        metavar="REPEAT")

    args = parser.parse_args()

    run(args)
