fuzzing_stub = '''
import atheris
import sys

def BVADD(x, y):
    return (x + y) % 2**256

def BVSUB(x, y):
    return (x - y) % 2**256

def BVMUL(x, y, size=256):
    return (x * y) % 2**size

def F_EVM_BVMUL_256(x, y):
    return BVMUL(x, y, size=256)

def F_EVM_BVUDIV_256(x, y):
    if y == 0:
        return 0
    return (x // y) % 2**256

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
    return (x % 2**(hi+1)) / 2**lo

def mk_int(data, idx):
    if len(data) < idx[0]+32:
        raise Skip
    res = int.from_bytes(data[idx[0]:idx[0]+32], "big")
    idx[0] += 32
    return res

class Skip(Exception):
    pass

def assume(cond):
    if not cond:
        raise Skip
'''
