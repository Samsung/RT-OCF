#!/usr/bin/env python
import sys
import os

MOCK = 'Mock'
IOTIVITY_RT_ROOT = os.path.abspath(
    os.path.join(os.path.dirname(__file__), ".."))
MOCK_DIR = os.path.abspath(os.path.join(IOTIVITY_RT_ROOT, "os/linux/mocks"))


def is_include_list(target_src, src_list):
    for index, src in enumerate(src_list):
        if target_src in src:
            return index
    return -1


def find_mock_list(file_name, src_list):
    f = open(file_name, 'r')
    while True:
        line = f.readline()
        if '#include' in line and 'Mock' in line and '//' not in line:
            mock_name = get_file_name(line)
            target_src = mock_name + '.o'
            mock_src = os.path.join(MOCK_DIR, MOCK + mock_name + '.c')
            position = is_include_list(target_src, src_list)
            if -1 is not position:
                src_list[position] = mock_src
            else:
                src_list.append(mock_src)
        if not line:
            break

    f.close()

    return src_list


def get_file_name(include_str):
    start = include_str.find('Mock')
    end = include_str.find('.h')
    return include_str[start + 4:end]


def find_test_file_path(name):
    for (path, dir, files) in os.walk(IOTIVITY_RT_ROOT):
        for filename in files:
            if filename != name:
                continue
            return os.path.join(path, filename)


if __name__ == "__main__":
    result = find_mock_list(sys.argv[1], sys.argv[2:])
    for src in result:
        print(src)


def test_get_file_name():
    result = get_file_name('#include "Mocksocket.h"')
    assert 'socket' == result


def test_no_mock_header():
    result = find_mock_list('../utils/test/test_random.c',
                            ['rt_transport.c', 'select.c', 'socket.c', 'rt_util.c'])
    assert result == ['rt_transport.c', 'select.c', 'socket.c', 'rt_util.c']


def test_transport():
    result = find_mock_list('../messaging/test/test_transport.c',
                            ['rt_transport.c', 'select.c', 'socket.c', 'rt_util.c'])
    assert result == [
        'rt_transport.c',
        'select.c',
        os.path.join(
            MOCK_DIR,
            'Mocksocket.c'),
        'rt_util.c']


def test_transport_with_system_library():
    result = find_mock_list('../messaging/test/test_transport.c',
                            ['../../messaging/rt_transport.c', '../../utils/rt_util.c'])
    assert result == [
        '../../messaging/rt_transport.c',
        '../../utils/rt_util.c',
        os.path.join(
            MOCK_DIR,
            'Mocksocket.c')]
