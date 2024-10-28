fuzzing_stub = '''
import atheris
import sys
from eth_hash.auto import keccak
import random


def BVADD(*sizes):
    size = sizes[0]
    def _BVADD(*lst):
        return sum(lst) % 2**size
    return _BVADD

def BVSUB(*sizes):
    size = sizes[0]
    def _BVSUB(x, y):
        return (x - y) % 2**size
    return _BVSUB

def BVMUL(*sizes):
    size = sizes[0]
    def _BVMUL(x, y):
        return (x * y) % 2**size
    return _BVMUL

def F_EVM_BVMUL_256(x, y):
    return BVMUL(256)(x, y)

def F_EVM_BVUDIV_256(x, y):
    if y == 0:
        return 0
    return (x // y) % 2**256

def F_EVM_BVUREM_256(x, y):
    if y == 0:
        return 0
    return x % y

def IF(c, x, y):
    return x if c else y

def AND(x, y):
    return x and y

def OR(x, y):
    return x or y

def NOT(x):
    return not x

def EQ(x, y):
    return x == y

def BVULE(x, y):
    return x <= y

def EXTRACT(hi, lo, x):
    return (x % 2**(hi+1)) // 2**lo

def CONCAT(*sizes):
    def _concat(*args):
        if len(args) != len(sizes):
            raise ValueError(args, sizes)
        result = 0
        for arg, size in zip(args, sizes):
            if arg >= 2**size:
                raise ValueError(arg, size)
            result <<= size
            result += arg
        return result
    return _concat

def STORE(d, k, v):
    return d | {k : v}

def SELECT(d, k):
    return d[k]

def F_SHA3_256(x):
    if isinstance(x, int):
        data = x.to_bytes(32, "big")

    else:
        raise ValueError(x)

    return int.from_bytes(keccak(data), "big")

def mk_int(data, idx):
    return random.randrange(1000000000000000000000000000)
#   if len(data) < idx[0]+32:
#       raise Skip
#   res = int.from_bytes(data[idx[0]:idx[0]+32], "big")
#   idx[0] += 32
#   return res

class Skip(Exception):
    pass

def assume(cond):
    if not cond:
        raise Skip
'''
