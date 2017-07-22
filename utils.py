from random import SystemRandom
from enum import IntEnum as _IntEnum
import string

def random_token(length=16) -> str:
    return ''.join(SystemRandom().choices(string.ascii_uppercase + string.digits, k=length))

class _AllOfThem():
    def __contains__(self, _):
        return True
all_of_them = _AllOfThem()

class IntEnum(_IntEnum):
    '''for easy db inserts'''
    def __str__(self, *args, **kwargs):
        return str(int(self))

def run_some(x, f):
    if x is None:
        return
    return f(x)
