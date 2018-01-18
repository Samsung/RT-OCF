import os
import re
import subprocess
from internal.utils import execute_return_output
from internal.common import Result

leak_message_re = re.compile(r"########## Memory Leak Occurs: \[[\s]+(?P<leak_byte>[\d]+) bytes]", re.MULTILINE)


class LeakCalculator:
    def __init__(self):
        pass

    def calculate(self, output):
        return self.parse_valgrind_leak_result(output)

    def parse_valgrind_leak_result(self, data):
        data = '\n'.join([line for line in data.split('\n') if 'simple_client' not in line])
        if '####### Memory Leak Occurs' not in data:
            return 0
        match = leak_message_re.search(data)
        if match is None:
            return 0
        return int(match.groupdict()['leak_byte'])