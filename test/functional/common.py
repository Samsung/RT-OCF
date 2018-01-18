from threading import Thread
from Queue import Queue, Empty
import sys

class NonBlockingStreamReader:
    def __init__(self, stream, name):
        self._s = stream
        self._q = Queue()
        self._name = name

        def _populateQueue(stream, queue):
            while True:
                line = stream.readline()
                if line:
                    queue.put(line)
                    sys.stdout.write("[{}]{}".format(self._name, line))
                    sys.stdout.flush()
                else:
                    return

        self._t = Thread(target = _populateQueue,
                args = (self._s, self._q))
        self._t.daemon = True
        self._t.start() #start collecting lines from the stream

    def readline(self, timeout = None):
        try:
            return self._q.get(block = timeout is not None,
                    timeout = timeout)
        except Empty:
            return None

class UnexpectedEndOfStream(Exception): pass

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_fail(str):
    print(bcolors.FAIL + str + bcolors.ENDC)

