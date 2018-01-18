#!/usr/bin/env python
import subprocess
import os
import sys

from internal.tizenrt_adapter import TizenRTAdapter


def run(args):
    adapter = TizenRTAdapter('')
    adapter.flash_binary(is_flash_all=args.all)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description='Use to install binaries on board.')

    parser.add_argument(
        "--all",
        dest="all",
        required=False,
        action='store_true',
        help="True, if you want to flash all.")
    args = parser.parse_args()

    run(args)
