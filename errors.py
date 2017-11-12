''' Errors '''

class BadKeyError(Exception):
    ''' Thrown when the key does not match '''

    def __init__(self):
        super(BadKeyError, self).__init__('bad key used')
