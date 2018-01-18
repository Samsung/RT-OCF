#!/usr/bin/env python
import subprocess
import os
import sys

from internal.common import Result
from internal.utils import write_result

from internal.linux_adapter import LinuxAdapter
from internal.tizenrt_adapter import TizenRTAdapter
from internal.iotivity_rt_error import IotivityRTError

from internal.config import CI_LINUX_BUILD_FILE_NAME
from internal.config import CI_TIZENRT_BUILD_FILE_NAME


def build_linux(args):
    result = Result(message='Successfully finished..')
    try:
        adapter = LinuxAdapter()
        if args.rebuild:
            adapter.distclean()
        adapter.build()
    except IotivityRTError as e:
        result = Result(exitcode=e.exitcode, message=e.message)
    finally:
        if args.is_ci:
            write_result(CI_LINUX_BUILD_FILE_NAME, result.message)
    return result


def build_tizenrt(args):
    result = Result(message='Successfully finished..')
    try:
        adapter = TizenRTAdapter(config=args.config)
        if args.rebuild:
            adapter.distclean()
            adapter.reconfig()
        adapter.build()
        if args.with_flash:
            adapter.flash_binary()
    except IotivityRTError as e:
        result = Result(exitcode=e.exitcode, message=e.message)
    finally:
        if args.is_ci:
            write_result(CI_TIZENRT_BUILD_FILE_NAME, result.message)
    return result


def run(args):
    if args.platform == 'linux':
        result = build_linux(args)
    elif args.platform == 'tizenrt':
        result = build_tizenrt(args)

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
        description='Linux Build',
        help='Build iotivity-rt project in linux environment.')
    parser_linux.add_argument(
        '--rebuild',
        dest="rebuild",
        required=False,
        action='store_true',
        help="True, Build after clean")
    parser_linux.add_argument(
        "--ci",
        dest="is_ci",
        required=False,
        action='store_true',
        help="True, if it is ci build.")

    parser_tizenrt = subparsers.add_parser(
        'tizenrt',
        description='Tizen RT Build',
        help='Build iotivity-rt project with TizenRT.')
    parser_tizenrt.add_argument(
        "--rebuild",
        dest="rebuild",
        required=False,
        action='store_true',
        help="True, Build after clean")
    parser_tizenrt.add_argument(
        '--config',
        dest="config",
        default='artik053/zeroroot',
        required=False,
        help="Select the config you want to use for the TizenRT build.")
    parser_tizenrt.add_argument(
        '--with-flash',
        dest="with_flash",
        required=False,
        action='store_true',
        help="True, if you want to flash binary after building")
    parser_tizenrt.add_argument(
        "--ci",
        dest="is_ci",
        required=False,
        action='store_true',
        help="True, if it is ci build.")

    args = parser.parse_args()

    run(args)
