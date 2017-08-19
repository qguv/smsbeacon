from random import SystemRandom
from enum import IntEnum as _IntEnum
import string

def random_token(length=16) -> str:
    return ''.join(SystemRandom().choices(string.ascii_uppercase + string.digits, k=length))

def normal_telno(telno):
    telno = ''.join([ c for c in telno if c in string.digits ])
    return '1' + telno if len(telno) == 10 else telno

class _AllOfThem():
    def __contains__(self, _):
        return True
all_of_them = _AllOfThem()

class IntEnum(_IntEnum):
    '''for easy db inserts'''
    def __str__(self, *args, **kwargs):
        return str(int(self))

def maybe_call(f, *args):
    if f is None:
        return

    for arg in args:
        if arg is None:
            return

    return f(*args)
