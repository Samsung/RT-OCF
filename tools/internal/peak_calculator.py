import os
import glob
import re
from internal.utils import execute
from internal.utils import execute_return_output
from internal.common import Result

class Peak:
    def __init__(self):
        self.total = 0
        self.useful_heap = 0
        self.extra_heap = 0
        self.stacks = 0

    def __str__(self):
        output = 'total:{}, '.format(self.total)
        output += 'useful_heap:{}, '.format(self.useful_heap)
        output += 'extra_heap:{}, '.format(self.extra_heap)
        output += 'stacks:{}'.format(self.stacks)
        return output

    def __repr__(self):
        return self.__str__()

    def __lt__(self, other):
        return self.total < other.total

    def __gt__(self, other):
        return other.__lt__(self)

    def __eq__(self, other):
        return self.total == other.total

    def __ne__(self, other):
        return not self.__eq__(other)


class PeakCalculator:
    def __init__(self):
        pass

    def calculate(self, data):
        return self.parse_massif(data)

    def parse_massif(self, massif_data):
        target_snapshot = self.find_peak_memory_snap_no(massif_data)
        return self.find_memory_info_by_snap_no(massif_data, target_snapshot)

    def find_peak_memory_snap_no(self, massif_data):
        peak_re = re.compile('(?P<snap_no>\d+) \(peak\)')
        result = peak_re.findall(massif_data)
        if len(result) is 0:
            return None
        return result[0]

    def find_memory_info_by_snap_no(self, massif_data, snap_no):
        memory_info_re = r"^\s+{}\s+([0-9,]+)\s+(?P<total>[0-9,]+)\s+(?P<useful_heap>[0-9,]+)\s+(?P<extra_heap>[0-9,]+)\s+(?P<stacks>[0-9,]+)".format(snap_no)
        compiled_re = re.compile(memory_info_re, re.MULTILINE)
        m = compiled_re.search(massif_data)
        if m is None:
            return None
        dic = m.groupdict()
        peak = Peak()
        peak.total = int(dic['total'].replace(',', ''))
        peak.useful_heap = int(dic['useful_heap'].replace(',', ''))
        peak.extra_heap = int(dic['extra_heap'].replace(',', ''))
        peak.stacks = int(dic['stacks'].replace(',', ''))
        return peak
