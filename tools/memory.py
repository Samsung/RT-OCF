#!/usr/bin/env python
import subprocess
import os
import sys

from internal.common import Result
from internal.utils import write_result
from internal.utils import execute
from internal.utils import execute_return_output

from internal.linux_adapter import LinuxAdapter
from internal.leak_calculator import LeakCalculator
from internal.peak_calculator import PeakCalculator
from internal.peak_calculator import Peak

from internal.iotivity_rt_error import IotivityRTError

from internal.config import IOTIVITY_RT_FUNCTIONAL_TEST

from internal.config import CI_LINUX_LEAK_FILE_NAME
from internal.config import CI_LINUX_PEAK_FILE_NAME

import glob

FUNCTIONAL_TESTS = glob.glob(os.path.join(IOTIVITY_RT_FUNCTIONAL_TEST, 'test_*.py'))

PEAK_FAIL_MESSAGE = "Calculating memory peak is Failed T^T"
LEAK_FAIL_MESSAGE = "Calculating memory leak is Failed T^T"

def run(args):
    adapter = LinuxAdapter()

    if not args.skip_build:
        adapter.distclean()
        adapter.build()
    result = Result()
    leak_message = LEAK_FAIL_MESSAGE
    peak_message = PEAK_FAIL_MESSAGE
    try:
        leak_dic = {}
        peak_dic = {}
        for binary in FUNCTIONAL_TESTS:
            filename = os.path.basename(binary)
            execute('rm -rf massif.out.*')
            execute_output = execute_return_output('python {}'.format(binary))
            leak_dic[filename] = LeakCalculator().calculate(execute_output.data)
            massif_output = execute_return_output('ms_print massif.out.*')
            peak_dic[filename] = PeakCalculator().calculate(massif_output.data)
            
        
        leak_total = 0
        peak_max = Peak()
        for filename in leak_dic:
            print('#############################################################')
            print('-- {} --'.format(filename))
            print('  Memory leak')
            print('    {} bytes'.format(leak_dic[filename]))
            print('  Memory peak')
            print('    {}'.format(str(peak_dic[filename])))
            print('#############################################################')
            leak_total += leak_dic[filename]
            if peak_dic[filename] > peak_max:
                peak_max = peak_dic[filename]
        leak_message = 'Memory Leak: {} bytes'.format(str(leak_total))
        peak_message = 'Memory Peak: {}'.format(str(peak_max))
    except IotivityRTError as e:
        peak_message = PEAK_FAIL_MESSAGE
        leak_message = LEAK_FAIL_MESSAGE
        result = Result(exitcode=e.exitcode, message=e.message)
    finally:
        if args.is_ci:
            write_result(CI_LINUX_LEAK_FILE_NAME, leak_message)
            write_result(CI_LINUX_PEAK_FILE_NAME, peak_message)

    print("Result::")
    print(leak_message)
    print(peak_message)
    exit(result.exitcode)


    


def run_peak(is_ci):
    try:
        result = PeakCalculator().calculate(FUNCTIONAL_TESTS)
    except IotivityRTError as e:
        result = Result(exitcode=e.exitcode, message=e.message)
    finally:
        if args.is_ci:
            write_result(CI_LINUX_PEAK_FILE_NAME, result.message)
    return result


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--skip-build',
        dest="skip_build",
        required=False,
        action='store_true',
        help="True, if you want to skip build")
    parser.add_argument(
        "--ci",
        dest="is_ci",
        required=False,
        action='store_true',
        help="True, if it is ci build.")

    args = parser.parse_args()

    run(args)
