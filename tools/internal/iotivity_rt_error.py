class RT_OCFError(Exception):
    def __init__(self, exitcode, message='', output=''):
        self.exitcode = exitcode
        self.message = message
        self.output = output

    def __str__(self):
        return 'exitcode: {}, message: {}'.format(self.exitcode, self.message)
