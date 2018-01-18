#!/usr/bin/env python

import glob
import serial
import sys
from internal.common import Result
import time

WIFI_SSID = 'ZEROROOT'
WIFI_PASSWORD = 'zeroroot'

class TestResultCollector:
    def __init__(self, usb_device=None):
        if usb_device is None:
            usb_device = self.get_usb_tty_number()
        self.serial = self.create_serial(usb_device)

    def get_usb_tty_number(self):
        ttyUSBs = glob.glob('/sys/class/tty/ttyUSB*')
        if len(ttyUSBs) == 0:
            print('TizenRT is not connected')
            exit(1)
        return '/dev/{}'.format(ttyUSBs[0].split('/')[-1])

    def create_serial(self, usb_device):
        return serial.Serial(usb_device, 115200, timeout=70)

    def collect(self, options=''):
        time.sleep(2)
        self.write_connecting_wifi_command()
        command = 'iot_rt_unittest ' + options + '\n'
        self.serial.write(command)
        return self.read_serial_output()
    
    def write_connecting_wifi_command(self):
        self.serial.write('wifi startsta\n')
        time.sleep(2)
        self.serial.write('wifi join {} {} wpa2_aes\n'.format(WIFI_SSID, WIFI_PASSWORD))
        time.sleep(2)
        self.serial.write('ifconfig wl1 dhcp\n')
        time.sleep(2)

    def read_serial_output(self):
        while True:
            line = self.serial.readline()
            if line == '':
                print('Timeout')
                return Result(exitcode=1,
                              message='timeout: Core Dump may occur')
            sys.stdout.write(line)
            if self.is_test_result(line):
                return Result(
                    exitcode=self.get_test_exitcode(line),
                    message=line)
            if self.is_core_dump(line):
                return Result(exitcode=1, message=line)

    def get_test_exitcode(self, line):
        arr = line.split(' ')
        if arr[2] == '0':
            return 0
        return 1

    def is_test_result(self, line):
        return 'Tests' in line and 'Failure' in line and 'Ignored' in line

    def is_core_dump(self, line):
        return '(core dumped)' in line


def test_get_usb_tty_number():
    assert '/dev/ttyUSB1' == TestResultCollector().get_usb_tty_number()


def test_create_serial():
    assert None != TestResultCollector().create_serial('/dev/ttyUSB1')


def test_is_core_dump():
    assert True == TestResultCollector().is_core_dump('Aborted (core dumped)')
