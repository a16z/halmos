# SPDX-License-Identifier: AGPL-3.0

import math
import subprocess

from copy import deepcopy
from collections import defaultdict
from typing import List, Dict, Tuple, Any

from z3 import *
from .byte2op import SrcMap, Opcode, decode

# z3 options
set_option(timeout=500)
set_option(max_width=240)
set_param(max_lines=100000000)

options = {}

Word = Any # z3 expression (including constants)
Byte = Any # z3 expression (including constants)

def wload(mem: List[Byte], loc: int, size: int) -> Word:
    return simplify(Concat(mem[loc:loc+size])) # BitVecSort(size * 8)

def wstore(mem: List[Byte], loc: int, size: int, val: Word) -> None:
    if not eq(val.sort(), BitVecSort(size*8)): raise ValueError(val)
    for i in range(size):
        mem[loc + i] = simplify(Extract((size-1 - i)*8+7, (size-1 - i)*8, val))

def wstore_bytes(mem: List[Byte], loc: int, size: int, arr: List[Byte]) -> None:
    if not size == len(arr): raise ValueError(size, arr)
    for i in range(size):
        if not eq(arr[i].sort(), BitVecSort(8)): raise ValueError(arr)
        mem[loc + i] = arr[i]

class State:
    stack: List[Word]
    memory: List[Byte]

    def __init__(self) -> None:
        self.stack: List[Word] = []
        self.memory: List[Byte] = []

    def __deepcopy__(self, memo):
        st = State()
        st.stack = deepcopy(self.stack)
        st.memory = deepcopy(self.memory)
        return st

    def __str__(self) -> str:
        return ''.join([
            'Stack: ', str(self.stack), '\n',
            self.str_memory() if options.get('memory') else '',
        ])

    def str_memory(self) -> str:
        idx: int = 0
        ret: str = 'Memory:'
        size: int = len(self.memory)
        while idx < size:
            ret = ret + '\n' + '- ' + str(hex(idx)) + ': ' + str(self.memory[idx:min(idx+32,size)])
            idx = idx + 32
        return ret + '\n'

    def push(self, v: Word) -> None:
        if not (eq(v.sort(), BitVecSort(256)) or eq(v.sort(), BoolSort())): raise ValueError(v)
        self.stack.insert(0, simplify(v))

    def pop(self) -> Word:
        v = self.stack[0]
        del self.stack[0]
        return v

    def dup(self, n: int) -> None:
        self.push(self.stack[n-1])

    def swap(self, n: int) -> None:
        tmp = self.stack[0]
        self.stack[0] = self.stack[n]
        self.stack[n] = tmp

    def mloc(self) -> int:
        loc: int = int(str(self.pop())) # loc must be concrete
        while len(self.memory) < loc + 32:
            self.memory.extend([BitVecVal(0, 8) for _ in range(32)])
        return loc

    def mstore(self, full: bool) -> None:
        loc: int = self.mloc()
        val: Word = self.pop()
        if eq(val.sort(), BoolSort()):
            val = If(val, con(1), con(0))
        if full:
            wstore(self.memory, loc, 32, val)
        else: # mstore8
            wstore_bytes(self.memory, loc, 1, [simplify(Extract(7, 0, val))])

    def mload(self) -> None:
        loc: int = self.mloc()
        self.push(wload(self.memory, loc, 32))

    def ret(self) -> Word:
        loc: int = self.mloc()
        size: int = int(str(self.pop())) # size (in bytes) must be concrete
        if size > 0:
            return wload(self.memory, loc, size)
        else:
            return None

def con(n: int) -> Word:
    return BitVecVal(n, 256)

f_calldataload = Function('calldataload', BitVecSort(256), BitVecSort(256)) # index
f_calldatasize = Function('calldatasize', BitVecSort(256))
f_callvalue = Function('callvalue', BitVecSort(256))
f_caller = Function('caller', BitVecSort(256))
f_origin = Function('origin', BitVecSort(256))
f_address = Function('address', BitVecSort(256))
f_coinbase = Function('coinbase', BitVecSort(256))
f_extcodesize = Function('extcodesize', BitVecSort(256), BitVecSort(256)) # target address
f_gas = Function('gas', BitVecSort(256), BitVecSort(256)) # cnt
f_timestamp = Function('timestamp', BitVecSort(256))
f_chainid = Function('chainid', BitVecSort(256))
f_balance = Function('balance', BitVecSort(256), BitVecSort(256), BitVecSort(256)) # target address, cnt

# convert opcode list to opcode map
def ops_to_pgm(ops: List[Opcode]) -> List[Opcode]:
    pgm: List[Opcode] = [None for _ in range(ops[-1].pc + 1)]
    for o in ops:
        pgm[o.pc] = o
    return pgm

def simplify_cnts(cnts: Dict[str,int]) -> Dict[str,int]:
    new_cnts = defaultdict(int)

    for (op, cnt) in cnts.items():
        if (   op == 'STOP'
            or op == 'RETURN'
            or op == 'REVERT'
        ):
            new_cnts['_0_zero'] += cnt
        elif (
               op == 'JUMPDEST'
        ):
            new_cnts['_1_jumpdest'] += cnt
        elif (
               op == 'ADDRESS'
            or op == 'ORIGIN'
            or op == 'CALLER'
            or op == 'CALLVALUE'
            or op == 'CALLDATASIZE'
            or op == 'RETURNDATASIZE'
            or op == 'CODESIZE'
            or op == 'GASPRICE'
            or op == 'COINBASE'
            or op == 'TIMESTAMP'
            or op == 'NUMBER'
            or op == 'DIFFICULTY'
            or op == 'GASLIMIT'
            or op == 'POP'
            or op == 'PC'
            or op == 'MSIZE'
            or op == 'GAS'
            or op == 'CHAINID'
        ):
            new_cnts['_2_base'] += cnt
        elif (
               op == 'ADD'
            or op == 'SUB'
            or op == 'NOT'
            or op == 'LT'
            or op == 'GT'
            or op == 'SLT'
            or op == 'SGT'
            or op == 'EQ'
            or op == 'ISZERO'
            or op == 'AND'
            or op == 'OR'
            or op == 'XOR'
            or op == 'BYTE'
            or op == 'SHL'
            or op == 'SHR'
            or op == 'SAR'
            or op == 'CALLDATALOAD'
            or op == 'MLOAD'
            or op == 'MSTORE'
            or op == 'MSTORE8'
            or op == 'PUSH1' or op == 'PUSH2' or op == 'PUSH3' or op == 'PUSH4' or op == 'PUSH5' or op == 'PUSH6' or op == 'PUSH7' or op == 'PUSH8' or op == 'PUSH9' or op == 'PUSH10' or op == 'PUSH11' or op == 'PUSH12' or op == 'PUSH13' or op == 'PUSH14' or op == 'PUSH15' or op == 'PUSH16' or op == 'PUSH17' or op == 'PUSH18' or op == 'PUSH19' or op == 'PUSH20' or op == 'PUSH21' or op == 'PUSH22' or op == 'PUSH23' or op == 'PUSH24' or op == 'PUSH25' or op == 'PUSH26' or op == 'PUSH27' or op == 'PUSH28' or op == 'PUSH29' or op == 'PUSH30' or op == 'PUSH31' or op == 'PUSH32'
            or op == 'DUP1' or op == 'DUP2' or op == 'DUP3' or op == 'DUP4' or op == 'DUP5' or op == 'DUP6' or op == 'DUP7' or op == 'DUP8' or op == 'DUP9' or op == 'DUP10' or op == 'DUP11' or op == 'DUP12' or op == 'DUP13' or op == 'DUP14' or op == 'DUP15' or op == 'DUP16'
            or op == 'SWAP1' or op == 'SWAP2' or op == 'SWAP3' or op == 'SWAP4' or op == 'SWAP5' or op == 'SWAP6' or op == 'SWAP7' or op == 'SWAP8' or op == 'SWAP9' or op == 'SWAP10' or op == 'SWAP11' or op == 'SWAP12' or op == 'SWAP13' or op == 'SWAP14' or op == 'SWAP15' or op == 'SWAP16'
        ):
            new_cnts['_3_verylow'] += cnt
        elif (
               op == 'MUL'
            or op == 'DIV'
            or op == 'SDIV'
            or op == 'MOD'
            or op == 'SMOD'
            or op == 'SIGNEXTEND'
            or op == 'SELFBALANCE'
        ):
            new_cnts['_5_low'] += cnt
        else:
            new_cnts[op] = cnt

    return new_cnts

class Exec:
    pgm: List[Opcode]
    code: List[str]
    st: State
    pc: int
    sol: Solver
    storage: Dict[int,Any]
    output: Any
    log: List[Tuple[List[Word], Any]]
    balance: Any
    cnts: Dict[str,int]
    opt_int_add: bool
    calldata: List[Byte]
    sha3s: List[Tuple[Word,Word]]
    fs_sha3: Dict[int,Word]
    storages: List[Tuple[Any,Any]]
    path: List[Any]
    calls: List[Any]
    jumps: List[Dict[str,int]]

    def __init__(self, pgm: List[Opcode], code: List[str], st: State, pc: int, sol: Solver, storage: Dict[Any,Any], output: Any, log: List[Tuple[List[Word], Any]], balance: Any, cnts: Dict[str,int], opt_int_add: bool, calldata: List[Byte], sha3s: List[Any], fs_sha3: Dict[int,Word], storages: List[Any], path: List[Any], calls: List[Any], jumps: List[Dict[str,int]]) -> None:
        self.pgm = pgm
        self.code = code
        self.st = st
        self.pc = pc
        self.sol = sol
        self.storage = storage
        self.output = output
        self.log = log
        self.balance = balance
        self.cnts = cnts
        self.opt_int_add = opt_int_add
        self.calldata = calldata
        self.sha3s = sha3s
        self.fs_sha3 = fs_sha3
        self.storages = storages
        self.path = path
        self.calls = calls
        self.jumps = jumps

    def str_cnts(self) -> str:
        cnts = simplify_cnts(self.cnts)
        return ''.join([f'{x[0]}: {x[1]}\n' for x in sorted(cnts.items(), key=lambda x: x[0])])

    def str_solver(self) -> str:
        return '\n'.join([str(cond) for cond in self.sol.assertions()])

    def str_path(self) -> str:
        return ''.join(map(lambda x: '- ' + str(x) + '\n', filter(lambda x: str(x) != 'True', self.path)))

    def summary(self) -> str:
        return ''.join([
            str(self.pc), ' ', str(self.pgm[self.pc]), '\n',
            'stack3:  ', str(self.st.stack[0:3]), '\n',
            'storage: ', str(self.storage), '\n',
            'balance: ', str(self.balance), '\n',
            'output: ' , str(self.output) , '\n',
            'log: '    , str(self.log)    , '\n',
        ])

    def __str__(self) -> str:
        return ''.join([
            'PC: '              , str(self.pc), ' ', str(self.pgm[self.pc]), '\n',
            str(self.st),
            'Storage: '         , str(self.storage), '\n',
            'Balance: '         , str(self.balance), '\n',
        #   'Solver:\n'         , self.str_solver(), '\n',
            'Path:\n'           , self.str_path(),
            'Output: '          , str(self.output) , '\n',
            'Log: '             , str(self.log)    , '\n',
        #   'Opcodes:\n'        , self.str_cnts(),
        #   'Memsize: '         , str(len(self.st.memory)), '\n',
            'Storage updates:\n', ''.join(map(lambda x: '- ' + str(x) + '\n', self.storages)),
            'SHA3 hashes:\n'    , ''.join(map(lambda x: '- ' + str(x) + '\n', self.sha3s)),
            'External calls:\n' , ''.join(map(lambda x: '- ' + str(x) + '\n', self.calls)),
        #   'Calldata: '        , str(self.calldata), '\n',
        ])

    def next_pc(self) -> int:
        self.pc += 1
        while self.pgm[self.pc] is None:
            self.pc += 1

    def sinit(self, slot: int, keys):
        if slot not in self.storage:
            if len(keys) == 0:
                self.storage[slot] = BitVec(f'storage_slot_{str(slot)}', 256)
            else:
                self.storage[slot] = Array(f'storage_slot_{str(slot)}', BitVecSort(len(keys)*256), BitVecSort(256))

    def sload(self, loc: Word) -> Word:
        offsets = self.decode_storage_loc(loc)
        if not len(offsets) > 0: raise ValueError(offsets)
        slot, keys = int(str(offsets[0])), offsets[1:]
        self.sinit(slot, keys)
        if len(keys) == 0:
            return self.storage[slot]
        elif len(keys) == 1:
            return Select(self.storage[slot], keys[0])
        else:
            return Select(self.storage[slot], Concat(keys))

    def sstore(self, loc: Any, val: Any):
        offsets = self.decode_storage_loc(loc)
        if not len(offsets) > 0: raise ValueError(offsets)
        slot, keys = int(str(offsets[0])), offsets[1:]
        self.sinit(slot, keys)
        if len(keys) == 0:
            self.storage[slot] = val
        else:
            new_storage_var = Array(f'storage{self.cnt_sstore()}', BitVecSort(len(keys)*256), BitVecSort(256))
            if len(keys) == 1:
                new_storage = Store(self.storage[slot], keys[0], val)
            else:
                new_storage = Store(self.storage[slot], Concat(keys), val)
            self.sol.add(new_storage_var == new_storage)
            self.storage[slot] = new_storage_var
            self.storages.append((new_storage_var,new_storage))

    def decode_storage_loc(self, loc: Any) -> Any:
        if loc.decl().name() == 'sha3_512':
            args = loc.arg(0)
            offset, base = simplify(Extract(511, 256, args)), simplify(Extract(255, 0, args))
            return self.decode_storage_loc(base) + (offset,)
        elif loc.sort().name() == 'bv':
            return (loc,)
        else:
            raise ValueError(loc)

    def sha3(self) -> None:
        loc: int = self.st.mloc()
        size: int = int(str(self.st.pop())) # size (in bytes) must be concrete
        f_sha3 = Function('sha3_'+str(size*8), BitVecSort(size*8), BitVecSort(256))
        sha3 = f_sha3(wload(self.st.memory, loc, size))
        sha3_var = BitVec(f'sha3_var{self.cnt_sha3()}', 256)
        self.sol.add(sha3_var == sha3)
        self.assume_sha3_distinct(sha3_var, sha3)
        if size == 64: # for storage hashed location
            self.st.push(sha3)
        else:
            self.st.push(sha3_var)

    def assume_sha3_distinct(self, sha3_var, sha3):
        for (v,s) in self.sha3s:
            if s.decl().name() == sha3.decl().name(): # same size
            #   self.sol.add(Implies(sha3_var == v, sha3.arg(0) == s.arg(0)))
                self.sol.add(Implies(sha3.arg(0) != s.arg(0), sha3_var != v))
            else:
                self.sol.add(sha3_var != v)
        self.sol.add(sha3_var != con(0))
        self.sha3s.append((sha3_var, sha3))

    def cnt_call(self) -> int:
        return self.cnts['CALL'] + self.cnts['STATICCALL']
    def cnt_sstore(self) -> int:
        return self.cnts['SSTORE']
    def cnt_gas(self) -> int:
        return self.cnts['GAS']
    def cnt_balance(self) -> int:
        return self.cnts['BALANCE']
    def cnt_sha3(self) -> int:
        return self.cnts['SHA3']

def read_code(code: List[str], idx: int) -> str:
    if idx < len(code):
        return code[idx]
    else:
        return '00'

#             x  == b   if sort(x) = bool
# int_to_bool(x) == b   if sort(x) = int
def test(x: Word, b: bool) -> Word:
    if eq(x.sort(), BoolSort()):
        if b:
            return x
        else:
            return Not(x)
    elif x.sort().name() == 'bv':
        if b:
            return (x != con(0))
        else:
            return (x == con(0))
    else:
        raise ValueError(x)

def is_non_zero(x: Word) -> Word:
    return test(x, True)

def is_zero(x: Word) -> Word:
    return test(x, False)

def and_or(x: Word, y: Word, is_and: bool) -> Word:
    if eq(x.sort(), BoolSort()) and eq(y.sort(), BoolSort()):
        if is_and:
            return And(x, y)
        else:
            return Or(x, y)
    #elif x.sort().name() == 'bv' and y.sort().name() == 'bv':
    elif eq(x.sort(), BitVecSort(256)) and eq(y.sort(), BitVecSort(256)):
        if is_and:
            return (x & y)
        else:
            return (x | y)
    elif eq(x.sort(), BoolSort()) and eq(y.sort(), BitVecSort(256)):
        return and_or(If(x, con(1), con(0)), y, is_and)
    elif eq(x.sort(), BitVecSort(256)) and eq(y.sort(), BoolSort()):
        return and_or(x, If(y, con(1), con(0)), is_and)
    else:
        raise ValueError(x, y, is_and)

def and_of(x: Word, y: Word) -> Word:
    return and_or(x, y, True)

def or_of(x: Word, y: Word) -> Word:
    return and_or(x, y, False)

f_xor  = Function('evm_xor',  BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_add  = Function('evm_add',  BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_sub  = Function('evm_sub',  BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_mul  = Function('evm_mul',  BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_div  = Function('evm_div',  BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_mod  = Function('evm_mod',  BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_sdiv = Function('evm_sdiv', BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_smod = Function('evm_smod', BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_exp  = Function('evm_exp',  BitVecSort(256), BitVecSort(256), BitVecSort(256))

def wadd(w1: Word, w2: Word) -> Word:
    if eq(w1.sort(), BoolSort()):
        w1 = If(w1, con(1), con(0))
    if eq(w2.sort(), BoolSort()):
        w2 = If(w2, con(1), con(0))
    return f_add(w1, w2)

def wsub(w1: Word, w2: Word) -> Word:
    if eq(w1.sort(), BoolSort()):
        w1 = If(w1, con(1), con(0))
    if eq(w2.sort(), BoolSort()):
        w2 = If(w2, con(1), con(0))
    return f_sub(w1, w2)

def wmul(w1: Word, w2: Word) -> Word:
    if eq(w1.sort(), BoolSort()):
        w1 = If(w1, con(1), con(0))
    if eq(w2.sort(), BoolSort()):
        w2 = If(w2, con(1), con(0))
    if options.get('mul'):
        return w1 * w2
    else:
        return f_mul(w1, w2)

def wdiv(w1: Word, w2: Word) -> Word:
    if options.get('div'):
        return UDiv(w1, w2) # unsigned div (bvdiv)
    else:
        return f_div(w1, w2)

def b2i(w: Word) -> Word:
    if w.decl().name() == 'true':
        return con(1)
    if w.decl().name() == 'false':
        return con(0)
    if eq(w.sort(), BoolSort()):
        return If(w, con(1), con(0))
    else:
        return w

def is_power_of_two(x: int) -> bool:
    if x > 0:
        return not (x & (x - 1))
    else:
        return False

def arith(op: str, w1: Word, w2: Word, opt_int_add: bool) -> Word:
    w1 = b2i(w1)
    w2 = b2i(w2)
    if op == 'ADD':
        if options.get('add'):
            return w1 + w2
        if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
            return w1 + w2
        else:
            return wadd(w1, w2)
    elif op == 'SUB':
        if options.get('sub'):
            return w1 - w2
        if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
            return w1 - w2
        else:
            return wsub(w1, w2)
    elif op == 'MUL':
        if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
            return w1 * w2
        elif w1.decl().name() == 'bv':
            i1: int = int(str(w1)) # must be concrete
            if i1 == 0:
                return con(0)
            elif is_power_of_two(i1):
                return w2 << int(math.log(i1,2))
            else:
                return wmul(w1, w2)
        elif w2.decl().name() == 'bv':
            i2: int = int(str(w2)) # must be concrete
            if i2 == 0:
                return con(0)
            elif is_power_of_two(i2):
                return w1 << int(math.log(i2,2))
            else:
                return wmul(w1, w2)
        else:
            return wmul(w1, w2)
    elif op == 'DIV':
        if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
            return UDiv(w1, w2)
        elif w2.decl().name() == 'bv':
            i2: int = int(str(w2)) # must be concrete
            if i2 == 0:
                return con(0)
            elif is_power_of_two(i2):
                return UDiv(w1, w2)
            else:
                return wdiv(w1, w2)
        else:
            return wdiv(w1, w2)
    elif op == 'MOD':
        if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
            return URem(w1, w2)
        else:
            return f_mod(w1, w2)
    elif op == 'SDIV':
        if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
            return w1 / w2
        else:
            return f_sdiv(w1, w2)
    elif op == 'SMOD':
        if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
            return w1 % w2
        else:
            return f_smod(w1, w2)
    elif op == 'EXP':
        if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
            i1: int = int(str(w1)) # must be concrete
            i2: int = int(str(w2)) # must be concrete
            return con(i1 ** i2)
        else:
            return f_exp(w1, w2)
    else:
        raise ValueError(op)

def call(ex: Exec, static: bool) -> None:
    gas = ex.st.pop()
    to = ex.st.pop()
    if static:
        fund = con(0)
    else:
        fund = ex.st.pop()
    arg_loc: int = ex.st.mloc()
    arg_size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete
    ret_loc: int = ex.st.mloc()
    ret_size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete

    if not arg_size >= 0: raise ValueError(arg_size)
    if not ret_size >= 0: raise ValueError(ret_size)

    if options.get('sub'):
        ex.balance = ex.balance - fund
    else:
        ex.balance = f_sub(ex.balance, fund)

    # push exit code
    if arg_size > 0:
        f_call = Function('call_'+str(arg_size*8), BitVecSort(256), BitVecSort(256), BitVecSort(256), BitVecSort(256), BitVecSort(arg_size*8), BitVecSort(256))
        exit_code = f_call(con(ex.cnt_call()), gas, to, fund, wload(ex.st.memory, arg_loc, arg_size))
    else:
        f_call = Function('call_'+str(arg_size*8), BitVecSort(256), BitVecSort(256), BitVecSort(256), BitVecSort(256),                         BitVecSort(256))
        exit_code = f_call(con(ex.cnt_call()), gas, to, fund)
    exit_code_var = BitVec(f'call{ex.cnt_call()}', 256)
    ex.sol.add(exit_code_var == exit_code)
    ex.st.push(exit_code_var)

    # TODO: cover other precompiled
    if to == con(1): # ecrecover exit code is always 1
        ex.sol.add(exit_code_var != con(0))

    # TODO: The actual return data size may be different from the given ret_size.
    #       In that case, ex.output should be set to the actual return data.
    #       And, if the actual size is smaller than the given size, then the memory is updated only up to the actual size.

    # store return value
    if ret_size > 0:
        f_ret = Function('ret_'+str(ret_size*8), BitVecSort(256), BitVecSort(ret_size*8))
        ret = f_ret(exit_code_var)
        wstore(ex.st.memory, ret_loc, ret_size, ret)
        ex.output = ret
    else:
        ex.output = None

    ex.calls.append((exit_code_var, exit_code, ex.output))

def jumpi(ex: Exec, stack: List[Exec], step_id: int) -> None:
    target: int = int(str(ex.st.pop())) # target must be concrete
    cond: Word = ex.st.pop()

    ex.sol.push()
    cond_true = simplify(is_non_zero(cond))
    ex.sol.add(cond_true)
    if ex.sol.check() != unsat: # jump
        new_sol = SolverFor('QF_AUFBV')
        new_sol.add(ex.sol.assertions())
        new_path = deepcopy(ex.path)
        new_path.append(str(cond_true))
        new_ex = Exec(ex.pgm, ex.code, deepcopy(ex.st), target, new_sol, deepcopy(ex.storage), deepcopy(ex.output), deepcopy(ex.log), deepcopy(ex.balance), deepcopy(ex.cnts), ex.opt_int_add, ex.calldata, deepcopy(ex.sha3s), deepcopy(ex.fs_sha3), deepcopy(ex.storages), new_path, deepcopy(ex.calls), deepcopy(ex.jumps))
        stack.append((new_ex, step_id))
    ex.sol.pop()

    cond_false = simplify(is_zero(cond))
    ex.sol.add(cond_false)
    if ex.sol.check() != unsat:
        ex.path.append(str(cond_false))
        ex.next_pc()
        stack.append((ex, step_id))

def jump(ex: Exec, sm: SrcMap, src: int, dst: int) -> bool:

    jmp = {'src': src, 'dst': dst, 'jmp': sm.jump, 'cnt': 0}

    if sm.jump == 'i': # function call
        ex.jumps.append(jmp)
        return True

    if sm.jump == 'o': # function return
        for i in reversed(range(len(ex.jumps))):
            if ex.jumps[i]['jmp'] == 'i':
                if not ex.jumps[i]['src'] + 1 == dst:
                    if options.get('debug'):
                        print('warn: unmatched jumps', ex.jumps[i]['src'], dst)
                ex.jumps = ex.jumps[:i]
                return True
        raise ValueError(ex.jumps, sm, src, dst)

    # loop back edge
    if len(ex.jumps) > 0:
        last = ex.jumps[-1]
        if last['jmp'] == '-' and last['dst'] == dst:
            if not last['src'] == src:
                if options.get('debug'):
                    print('warn: unmatched src', last['src'], src)
            ex.jumps[-1]['cnt'] += 1
            if 'max_loop' in options:
                return ex.jumps[-1]['cnt'] < options['max_loop']
            else:
                return True

    ex.jumps.append(jmp)
    return True

def returndatasize(ex: Exec) -> int:
    if ex.output is None:
        return 0
    else:
        size: int = ex.output.sort().size()
        if not size % 8 == 0: raise ValueError(size)
        return int(size / 8)

Steps = Dict[int,Dict[str,Any]]

def run(ex0: Exec) -> Tuple[List[Exec], Steps]:
    out: List[Exec] = []
    steps: Steps = {}
    step_id: int = 0

    stack: List[Tuple[Exec,int]] = [(ex0, 0)]
    while stack:
        if 'max_width' in options and len(out) >= options['max_width']: break

        (ex, prev_step_id) = stack.pop()
        step_id += 1

        o = ex.pgm[ex.pc]
        ex.cnts[o.op[0]] += 1

        if 'max_depth' in options and sum(ex.cnts.values()) > options['max_depth']:
            continue

        if options.get('log'):
            if o.op[0] == 'JUMPI':
                steps[step_id] = {'parent': prev_step_id, 'exec': str(ex)}
        #   elif o.op[0] == 'CALL':
        #       steps[step_id] = {'parent': prev_step_id, 'exec': str(ex) + ex.st.str_memory() + '\n'}
            else:
                steps[step_id] = {'parent': prev_step_id, 'exec': ex.summary()}
            #   steps[step_id] = {'parent': prev_step_id, 'exec': str(ex)}
            if options.get('verbose', 0) >= 3:
                print(ex)

        if o.op[0] == 'STOP':
            ex.output = None
            out.append(ex)
            continue

        elif o.op[0] == 'REVERT':
            ex.output = ex.st.ret()
            out.append(ex)
            continue

        elif o.op[0] == 'RETURN':
            ex.output = ex.st.ret()
            out.append(ex)
            continue

        elif o.op[0] == 'JUMPI':
            jumpi(ex, stack, step_id)
            continue

        elif o.op[0] == 'JUMP':
            source: int = ex.pc
            target: int = int(str(ex.st.pop())) # target must be concrete
            ex.pc = target
            if not options.get('srcmap') or jump(ex, o.sm, source, target):
                stack.append((ex, step_id))
            continue

        elif o.op[0] == 'JUMPDEST':
            pass

        elif int('01', 16) <= int(o.hx, 16) <= int('07', 16): # ADD MUL SUB DIV SDIV MOD SMOD
            ex.st.push(arith(o.op[0], ex.st.pop(), ex.st.pop(), ex.opt_int_add))

        elif o.op[0] == 'EXP':
            ex.st.push(arith(o.op[0], ex.st.pop(), ex.st.pop(), ex.opt_int_add))

        elif o.op[0] == 'LT':
            w1 = b2i(ex.st.pop())
            w2 = b2i(ex.st.pop())
            ex.st.push(ULT(w1, w2))
        elif o.op[0] == 'GT':
            w1 = b2i(ex.st.pop())
            w2 = b2i(ex.st.pop())
            ex.st.push(UGT(w1, w2))
        elif o.op[0] == 'SLT':
            w1 = b2i(ex.st.pop())
            w2 = b2i(ex.st.pop())
            ex.st.push(w1 < w2)
        elif o.op[0] == 'SGT':
            w1 = b2i(ex.st.pop())
            w2 = b2i(ex.st.pop())
            ex.st.push(w1 > w2)

        elif o.op[0] == 'EQ':
            w1 = ex.st.pop()
            w2 = ex.st.pop()
            if eq(w1.sort(), w2.sort()):
                ex.st.push(w1 == w2)
            else:
                if eq(w1.sort(), BoolSort()):
                    if not eq(w2.sort(), BitVecSort(256)): raise ValueError(w2)
                    ex.st.push(If(w1, con(1), con(0)) == w2)
                else:
                    if not eq(w1.sort(), BitVecSort(256)): raise ValueError(w1)
                    if not eq(w2.sort(), BoolSort()):      raise ValueError(w2)
                    ex.st.push(w1 == If(w2, con(1), con(0)))
        elif o.op[0] == 'ISZERO':
            ex.st.push(is_zero(ex.st.pop()))

        elif o.op[0] == 'AND':
            ex.st.push(and_of(ex.st.pop(), ex.st.pop()))
        elif o.op[0] == 'OR':
            ex.st.push(or_of(ex.st.pop(), ex.st.pop()))
        elif o.op[0] == 'NOT':
            ex.st.push(~ ex.st.pop())
        elif o.op[0] == 'SHL':
            w = ex.st.pop()
            ex.st.push(b2i(ex.st.pop()) << b2i(w))
        elif o.op[0] == 'SAR':
            w = ex.st.pop()
            ex.st.push(ex.st.pop() >> w)
        elif o.op[0] == 'SHR':
            w = ex.st.pop()
            ex.st.push(LShR(ex.st.pop(), w))

        elif o.op[0] == 'XOR':
            ex.st.push(f_xor(ex.st.pop(), ex.st.pop()))

        elif o.op[0] == 'CALLDATALOAD':
            if ex.calldata is None:
                ex.st.push(f_calldataload(ex.st.pop()))
            else:
                offset: int = int(str(ex.st.pop()))
                ex.st.push(Concat(ex.calldata[offset:offset+32]))
            #   try:
            #       offset: int = int(str(ex.st.pop()))
            #       ex.st.push(Concat(ex.calldata[offset:offset+32]))
            #   except:
            #       ex.st.push(f_calldataload(ex.st.pop()))
        elif o.op[0] == 'CALLDATASIZE':
            if ex.calldata is None:
                ex.st.push(f_calldatasize())
            else:
                ex.st.push(con(len(ex.calldata)))
        elif o.op[0] == 'CALLVALUE':
            ex.st.push(f_callvalue())
        elif o.op[0] == 'CALLER':
            ex.st.push(f_caller())
            ex.sol.add(Extract(255, 160, f_caller()) == BitVecVal(0, 96))
        elif o.op[0] == 'ORIGIN':
            ex.st.push(f_origin())
            ex.sol.add(Extract(255, 160, f_origin()) == BitVecVal(0, 96))
        elif o.op[0] == 'ADDRESS':
            ex.st.push(f_address())
            ex.sol.add(Extract(255, 160, f_address()) == BitVecVal(0, 96))
        elif o.op[0] == 'COINBASE':
            ex.st.push(f_coinbase())
            ex.sol.add(Extract(255, 160, f_coinbase()) == BitVecVal(0, 96))
        elif o.op[0] == 'EXTCODESIZE':
            ex.st.push(f_extcodesize(ex.st.pop()))
        elif o.op[0] == 'CODESIZE':
            ex.st.push(con(len(ex.code)))
        elif o.op[0] == 'GAS':
            ex.st.push(f_gas(con(ex.cnt_gas())))
        elif o.op[0] == 'TIMESTAMP':
            ex.st.push(f_timestamp())

        elif o.op[0] == 'CHAINID':
        #   ex.st.push(f_chainid())
            ex.st.push(con(1)) # for ethereum

        elif o.op[0] == 'BALANCE':
            ex.st.push(f_balance(ex.st.pop(), con(ex.cnt_balance())))
        elif o.op[0] == 'SELFBALANCE':
            ex.st.push(ex.balance)

        elif o.op[0] == 'CALL':
            call(ex, False)
        elif o.op[0] == 'STATICCALL':
            call(ex, True)

        elif o.op[0] == 'SHA3':
            ex.sha3()

        elif o.op[0] == 'POP':
            ex.st.pop()
        elif o.op[0] == 'MLOAD':
            ex.st.mload()
        elif o.op[0] == 'MSTORE':
            ex.st.mstore(True)
        elif o.op[0] == 'MSTORE8':
            ex.st.mstore(False)

        elif o.op[0] == 'SLOAD':
            ex.st.push(ex.sload(ex.st.pop()))
        elif o.op[0] == 'SSTORE':
            ex.sstore(ex.st.pop(), ex.st.pop())

        elif o.op[0] == 'RETURNDATASIZE':
            ex.st.push(con(returndatasize(ex)))
        elif o.op[0] == 'RETURNDATACOPY':
            loc: int = ex.st.mloc()
            offset: int = int(str(ex.st.pop())) # offset must be concrete
            size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete
            if size > 0:
                datasize: int = returndatasize(ex)
                if not datasize >= offset + size: raise ValueError(datasize, offset, size)
                data = Extract((datasize-1 - offset)*8+7, (datasize - offset - size)*8, ex.output)
                wstore(ex.st.memory, loc, size, data)

        elif o.op[0] == 'CALLDATACOPY':
            loc: int = ex.st.mloc()
            offset: int = int(str(ex.st.pop())) # offset must be concrete
            size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete
            if size > 0:
                while len(ex.st.memory) < loc + size:
                    ex.st.memory.extend([BitVecVal(0, 8) for _ in range(32)])
                if ex.calldata is None:
                    f_calldatacopy = Function('calldatacopy_'+str(size*8), BitVecSort(256), BitVecSort(size*8))
                    data = f_calldatacopy(offset)
                    wstore(ex.st.memory, loc, size, data)
                else:
                    if offset + size <= len(ex.calldata):
                        wstore_bytes(ex.st.memory, loc, size, ex.calldata[offset:offset+size])
                    elif offset == len(ex.calldata): # copy zero bytes
                        wstore_bytes(ex.st.memory, loc, size, [BitVecVal(0, 8) for _ in range(size)])
                    else:
                        raise ValueError(offset, size, len(ex.calldata))

        elif o.op[0] == 'CODECOPY':
            loc: int = ex.st.mloc()
            pc: int = int(str(ex.st.pop())) # pc must be concrete
            size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete
            while len(ex.st.memory) < loc + size:
                ex.st.memory.extend([BitVecVal(0, 8) for _ in range(32)])
            for i in range(size):
                ex.st.memory[loc + i] = BitVecVal(int(read_code(ex.code, pc + i), 16), 8)

        elif o.op[0] == 'BYTE':
            idx: int = int(str(ex.st.pop())) # index must be concrete
            if not (idx >= 0 and idx < 32): raise ValueError(idx)
            w = ex.st.pop()
            ex.st.push(ZeroExt(248, Extract((31-idx)*8+7, (31-idx)*8, w)))

        elif int('a0', 16) <= int(o.hx, 16) <= int('a4', 16): # LOG0 -- LOG4
            num_keys: int = int(o.hx, 16) - int('a0', 16)
            loc: int = ex.st.mloc()
            size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete
            keys = []
            for _ in range(num_keys):
                keys.append(ex.st.pop())
            ex.log.append((keys, wload(ex.st.memory, loc, size) if size > 0 else None))

        elif int('60', 16) <= int(o.hx, 16) <= int('7f', 16): # PUSH1 -- PUSH32
            ex.st.push(con(int(o.op[1], 16)))
        elif int('80', 16) <= int(o.hx, 16) <= int('8f', 16): # DUP1  -- DUP16
            ex.st.dup(int(o.hx, 16) - int('80', 16) + 1)
        elif int('90', 16) <= int(o.hx, 16) <= int('9f', 16): # SWAP1 -- SWAP16
            ex.st.swap(int(o.hx, 16) - int('90', 16) + 1)

        else:
            out.append(ex)
            continue

        ex.next_pc()
        stack.append((ex, step_id))

    return (out, steps)

def sevm(ops: List[Opcode], code: List[str], sol: Solver = SolverFor('QF_AUFBV'), storage = {}, output: Any = None, log = [], balance: Any = BitVec('balance', 256), cnts: Dict[str,int] = defaultdict(int), opt_int_add = False, calldata = None, opts = {}, sha3s = [], fs_sha3 = {}, storages = [], path = [], calls = [], jumps = []) -> Tuple[List[Exec], Steps]:
    global options
    options = opts
    st = State()
    ex = Exec(ops_to_pgm(ops), code, st, 0, sol, storage, output, log, balance + f_callvalue(), cnts, opt_int_add, calldata, sha3s, fs_sha3, storages, path, calls, jumps)
    return run(ex)

if __name__ == '__main__':
    hexcode: str = input()
    sevm(decode(hexcode))
