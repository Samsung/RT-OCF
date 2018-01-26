from subprocess import call
import os

from tools.internal.config import RT_OCF_ROOT

INVALID_FILEPATH = os.path.join(RT_OCF_ROOT, 'manager', 'invalid.c')


def make_fail_file():
    f = open(INVALID_FILEPATH, 'w')
    f.write('invalid!!!')
    f.close()


def remove_fail_file():
    call('rm -rf ' + INVALID_FILEPATH, shell=True)
