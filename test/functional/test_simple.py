#-*- coding: utf-8 -*-
import subprocess
import os
import sys
import time

from common import NonBlockingStreamReader
from common import print_fail
from common import bcolors

from threading import Thread
from Queue import Queue, Empty

RT_OCF_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
LINUX_BUILD_DIR = os.path.join(RT_OCF_ROOT, 'os', 'linux')
SIMPLE_SERVER = os.path.join(LINUX_BUILD_DIR, 'simple_server')
SIMPLE_CLIENT = os.path.join(LINUX_BUILD_DIR, 'simple_client')

SECURE_ENDPOINT_FLAG = 11
SECURE_ENDPOINT_FLAG = 11

class DiscoveryResource:
    def __init__(self):
        self.index = -1
        self.uri = ''
        self.address = ''
        self.port = -1
    def __str__(self):
        return '{}, {}, {}:{}'.format(self.index, self.uri, self.address, self.port)
    def __repr__(self):
        return self.__str__()

INPUT_PAYLOAD = 'simple_test'

def parse_discovery_resources(reader):
    discovery_resources = []
    current_resource = None
    while True:
        line = reader.readline(5)
        if not line:
            if len(discovery_resources) == 0:
                print_fail('output is empty')
                exit(1)
            return discovery_resources
        
        line = line[:-1]
        if 'show stored_remote_resources' in line:
            discovery_resources = []
            continue
        if 'uri: ' in line:
            current_resource = DiscoveryResource()
            current_resource.index = len(discovery_resources)
            current_resource.uri = line.split('uri: ')[1]
        if 'endpoint address: ' in line:
            current_resource.address = line.split('endpoint address: ')[1]
        if 'endpoint flag: ' in line:
            discovery_resources.append(current_resource)
        
def parse_server_port(reader):
    dtls_port = '-1'
    normal_port = '-1'
    while True:
        line = reader.readline(10) 
        if not line:
            print_fail('output is empty')
            exit(1)
        line = line[:-1]
        if 'UDP dtls Port' in line:
            dtls_port = line.split(': ')[1]
        if 'UDP normal Port' in line:
            normal_port = line.split(': ')[1]
            break
    return normal_port, dtls_port


def get_ip_address():
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    return s.getsockname()[0]


def write_result_file(filename, message):
    subprocess.call('rm -rf {}'.format(filename), shell=True)
    f = open(filename, 'w')
    f.write(message + '\n')
    f.close()

def run():
    ip_address = get_ip_address()
    print('  local ip address: {}'.format(ip_address))
    server_process = None
    client_process = None
    try:
        subprocess.call('rm -rf massif.out.*', shell=True)
        server_process = subprocess.Popen(['valgrind', '--tool=massif' ,'--stacks=yes' ,'--heap=yes', '--time-unit=B', SIMPLE_SERVER], stderr=subprocess.STDOUT, stdout=subprocess.PIPE, stdin=subprocess.PIPE)

        server_output_reader = NonBlockingStreamReader(server_process.stdout, bcolors.OKBLUE + 'simple_server' + bcolors.ENDC)

        (normal_port, dtls_port) = parse_server_port(server_output_reader)

        client_process = subprocess.Popen([SIMPLE_CLIENT], stdout=subprocess.PIPE, stdin=subprocess.PIPE)
        
        client_output_reader = NonBlockingStreamReader(client_process.stdout, bcolors.OKGREEN + 'simple_client' + bcolors.ENDC)

        client_process.stdin.write('d\n')
        # receive discovery result 
        discovery_resources = parse_discovery_resources(client_output_reader)
        loopback_resources = [resource for resource in discovery_resources if resource.address == ip_address]
        blue_resource = [resource for resource in loopback_resources if resource.uri == '/light/blue'][0]
        red_resource = [resource for resource in loopback_resources if resource.uri == '/light/red'][0]

        print(blue_resource)
        print(red_resource)
        print('Client >> select red_resource')
        client_process.stdin.write('s\n')
        client_process.stdin.write('{}\n'.format(red_resource.index))
        time.sleep(1)
        print('Client >> get red_resource')
        client_process.stdin.write('0\n')
        client_process.stdin.write('g\n')
        time.sleep(1)
        print('Client >> select blue_resource')
        client_process.stdin.write('s\n')
        client_process.stdin.write('{}\n'.format(blue_resource.index))
        client_process.stdin.write('0\n')
        time.sleep(1)
        print('Client >> get blue_resource')
        client_process.stdin.write('g\n')
        time.sleep(1)
        print('Client >> update blue_resource')
        client_process.stdin.write('u\n')
        time.sleep(1)
        print('Client >> get blue_resource')
        client_process.stdin.write('g\n')
        time.sleep(1)

        print('Client >> observe blue_resource')
        client_process.stdin.write('b\n')
        time.sleep(1)
        print('Server >> turn off blue_resource')
        server_process.stdin.write('b\n')
        server_process.stdin.write('0\n')
        time.sleep(1)
        

        #Close secure session
        server_process.stdin.write('q\n')
        client_process.stdin.write('q\n')
        
        server_process.wait()
        client_process.wait()
    finally:
        try:
            server_process.terminate()
        except OSError:
            pass
        try:
            client_process.terminate()
        except OSError:
            pass

if __name__ == "__main__":
    run()
    