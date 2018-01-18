#!/usr/bin/env python

import os
from subprocess import call


from internal.config import IOTIVITY_RT_ROOT
from internal.config import IOTIVITY_RT_ROOT_TOOLS
from internal.config import LINUX_BUILD_DIR
from internal.config import TIZEN_RT_BUILD_DIR

TIZENRT_MAKEDEFS_PATH = os.path.join(TIZEN_RT_BUILD_DIR, 'Make.defs')
TIZENRT_RUNNER_PATH = os.path.join(TIZEN_RT_BUILD_DIR, 'iot_test_runner.c')


class TizenRTTestGenerator:
    def __init__(self):
        self.makedefs = TIZENRT_MAKEDEFS_PATH
        self.runner = TIZENRT_RUNNER_PATH

    def generate(self):
        call('rm -rf {}'.format(self.makedefs), shell=True)
        call('rm -rf {}'.format(self.runner), shell=True)

        test_files = self.find_test_file_list()
        self.generate_makedefs(test_files)
        self.generate_test_runner(test_files)

    def generate_makedefs(self, test_files):
        print('Generate Make.defs...')
        f = open(self.makedefs, 'w')
        for file in test_files:
            f.write(
                file.replace(
                    IOTIVITY_RT_ROOT,
                    'CSRCS += $(IOTIVITYRT_ROOT)'))
            f.write('\n')
        f.close()

    def generate_test_runner(self, test_files):
        print('Generate iot_test_runner.c...')
        test_group_runners = self.retrieve_test_group_runners(test_files)
        data = self.read_template_test_runner()
        data = data.replace(
            '{{ RUN_TEST_GROUPS }}',
            '\n'.join(test_group_runners))
        self.write_test_runner(data)

    def read_template_test_runner(self):
        template_f = open(self.runner + '.template', 'r')
        data = template_f.read()
        template_f.close()
        return data

    def write_test_runner(self, data):
        runner_f = open(self.runner, 'w')
        runner_f.write(data)
        runner_f.close()

    def has_mock_header(self, filepath):
        f = open(filepath, 'r')
        for line in f.readlines():
            if line.startswith('#include "Mock'):
                return True
        return False

    def find_test_file_list(self):
        result = []
        for (path, dir, files) in os.walk(IOTIVITY_RT_ROOT):
            if 'os/linux/test' in path:
                continue
            if 'extlibs/' in path:
                continue
            for filename in files:
                ext = os.path.splitext(filename)[-1]
                if ext != '.c':
                    continue
                if not filename.startswith('test_'):
                    continue
                if filename == 'test_mem_kernel.c':
                    continue
                if filename == 'test_mem_buddy.c':
                    continue
                full_path = os.path.join(path, filename)
                if self.has_mock_header(full_path):
                    continue
                result.append(full_path)
        result.sort()
        return result

    def retrieve_test_group_runners(self, files):
        runners = []
        for file in files:
            f = open(file, 'r')
            for line in f.readlines():
                if line.startswith('TEST_GROUP'):
                    group_name = line.strip().replace('TEST_GROUP(', '')[:-2]
                    runners.append('\tRUN_TEST_GROUP({});'.format(group_name))
                    break
            f.close()
        return runners
