from random import SystemRandom
from enum import IntEnum as _IntEnum
import string

def random_token(length=16) -> str:
    return ''.join(SystemRandom().choices(string.ascii_uppercase + string.digits, k=length))

def normal_telno(telno):
    telno = telno.strip()

    # foreigners know their numbers better than we do
    foreign_number = telno[0] == '+' and telno[1] != '1'

    # only digits are valid
    telno = ''.join([ c for c in telno if c in string.digits ])

    if not foreign_number:
        telno = '1' + telno if len(telno) == 10 else telno

    return telno

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
