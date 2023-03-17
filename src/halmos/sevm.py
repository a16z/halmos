# SPDX-License-Identifier: AGPL-3.0

import json
import math

from copy import deepcopy
from collections import defaultdict
from typing import List, Dict, Set, Tuple, Any
from functools import reduce

from z3 import *
from .byte2op import Opcode, decode, concat
from .utils import EVM, color_good, color_warn, hevm_cheat_code, sha3_inv

Word = Any # z3 expression (including constants)
Byte = Any # z3 expression (including constants)
Bytes = Any # z3 expression (including constants)

Steps = Dict[int,Dict[str,Any]] # execution tree

# symbolic states
f_calldataload = Function('calldataload', BitVecSort(256), BitVecSort(256)) # index
f_calldatasize = Function('calldatasize', BitVecSort(256))
f_origin       = Function('origin'      , BitVecSort(256))
f_coinbase     = Function('coinbase'    , BitVecSort(256))
f_extcodesize  = Function('extcodesize' , BitVecSort(256), BitVecSort(256)) # target address
f_extcodehash  = Function('extcodehash' , BitVecSort(256), BitVecSort(256)) # target address
f_blockhash    = Function('blockhash'   , BitVecSort(256), BitVecSort(256)) # block number
f_gas          = Function('gas'         , BitVecSort(256), BitVecSort(256)) # cnt
f_gasprice     = Function('gasprice'    , BitVecSort(256))
f_timestamp    = Function('timestamp'   , BitVecSort(256))
f_blocknumber  = Function('blocknumber' , BitVecSort(256))
f_difficulty   = Function('difficulty'  , BitVecSort(256))
f_gaslimit     = Function('gaslimit'    , BitVecSort(256))
f_chainid      = Function('chainid'     , BitVecSort(256))
f_orig_balance = Function('orig_balance', BitVecSort(256), BitVecSort(256)) # target address

# uninterpreted arithmetic
f_add  = Function('evm_add' , BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_sub  = Function('evm_sub' , BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_mul  = Function('evm_mul' , BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_div  = Function('evm_div' , BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_mod  = Function('evm_mod' , BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_sdiv = Function('evm_sdiv', BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_smod = Function('evm_smod', BitVecSort(256), BitVecSort(256), BitVecSort(256))
f_exp  = Function('evm_exp' , BitVecSort(256), BitVecSort(256), BitVecSort(256))

def con(n: int) -> Word:
    return BitVecVal(n, 256)

def wextend(mem: List[Byte], loc: int, size: int) -> None:
    if len(mem) < loc + size:
        mem.extend([BitVecVal(0, 8) for _ in range(loc + size - len(mem))])

def wload(mem: List[Byte], loc: int, size: int) -> Bytes:
    wextend(mem, loc, size)
    return simplify(Concat(mem[loc:loc+size])) # BitVecSort(size * 8)

def wstore(mem: List[Byte], loc: int, size: int, val: Bytes) -> None:
    if not eq(val.sort(), BitVecSort(size*8)): raise ValueError(val)
    wextend(mem, loc, size)
    for i in range(size):
        mem[loc + i] = simplify(Extract((size-1 - i)*8+7, (size-1 - i)*8, val))

def wstore_partial(mem: List[Byte], loc: int, offset: int, size: int, data: Bytes, datasize: int) -> None:
    if size > 0:
        if not datasize >= offset + size: raise ValueError(datasize, offset, size)
        sub_data = Extract((datasize-1 - offset)*8+7, (datasize - offset - size)*8, data)
        wstore(mem, loc, size, sub_data)

def wstore_bytes(mem: List[Byte], loc: int, size: int, arr: List[Byte]) -> None:
    if not size == len(arr): raise ValueError(size, arr)
    wextend(mem, loc, size)
    for i in range(size):
        if not eq(arr[i].sort(), BitVecSort(8)): raise ValueError(arr)
        mem[loc + i] = arr[i]

def create_address(cnt: int) -> Word:
    return con(0x220E + cnt)

def valid_jump_destinations(pgm: List[Opcode]) -> Set[int]:
    jumpdests = set()
    i = 0
    while i < len(pgm):
        opcode = pgm[i].op[0]
        if is_bv_value(opcode):
            opcode = opcode.as_long()
            if opcode == EVM.JUMPDEST:
                jumpdests.add(i)
            elif EVM.PUSH1 <= opcode <= EVM.PUSH32:
                i += opcode - EVM.PUSH1 + 1
        i += 1
    return jumpdests

class State:
    stack: List[Word]
    memory: List[Byte]

    def __init__(self) -> None:
        self.stack: List[Word] = []
        self.memory: List[Byte] = []

    def __deepcopy__(self, memo): # -> State:
        st = State()
        st.stack = deepcopy(self.stack)
        st.memory = deepcopy(self.memory)
        return st

    def __str__(self) -> str:
        return ''.join([
            'Stack: ', str(self.stack), '\n',
            self.str_memory(),
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
        if not (eq(v.sort(), BitVecSort(256)) or is_bool(v)): raise ValueError(v)
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
        return loc

    def mstore(self, full: bool) -> None:
        loc: int = self.mloc()
        val: Word = self.pop()
        if is_bool(val):
            val = If(val, con(1), con(0))
        if full:
            wstore(self.memory, loc, 32, val)
        else: # mstore8
            wstore_bytes(self.memory, loc, 1, [simplify(Extract(7, 0, val))])

    def mload(self) -> None:
        loc: int = self.mloc()
        self.push(wload(self.memory, loc, 32))

    def ret(self) -> Bytes:
        loc: int = self.mloc()
        size: int = int(str(self.pop())) # size (in bytes) must be concrete
        if size > 0:
            return wload(self.memory, loc, size)
        else:
            return None

class Exec: # an execution path
    # network
    pgm: Dict[Any,List[Opcode]] # address -> { opcode map: pc -> opcode }
    code: Dict[Any,List[Any]] # address -> opcode sequence
    storage: Dict[Any,Dict[int,Any]] # address -> { storage slot -> value }
    balance: Dict[Any,Any] # address -> balance
    # tx
    calldata: List[Byte] # msg.data
    callvalue: Word # msg.value
    caller: Word # msg.sender
    this: Word # current account address
    # vm state
    pc: int
    st: State # stack and memory
    jumpis: Dict[str,Dict[bool,int]] # for loop detection
    output: Any # returndata
    symbolic: bool # symbolic or concrete storage
    # path
    solver: Solver
    path: List[Any] # path conditions
    # logs
    log: List[Tuple[List[Word], Any]] # event logs emitted
    cnts: Dict[int,int] # opcode -> frequency
    sha3s: List[Tuple[Word,Word]] # sha3 hashes generated
    storages: List[Tuple[Any,Any]] # storage updates
    calls: List[Any] # external calls
    failed: bool
    error: str

    def __init__(self, **kwargs) -> None:
        self.pgm      = kwargs['pgm']
        self.code     = kwargs['code']
        self.storage  = kwargs['storage']
        self.balance  = kwargs['balance']
        #
        self.calldata = kwargs['calldata']
        self.callvalue= kwargs['callvalue']
        self.caller   = kwargs['caller']
        self.this     = kwargs['this']
        #
        self.pc       = kwargs['pc']
        self.st       = kwargs['st']
        self.jumpis   = kwargs['jumpis']
        self.output   = kwargs['output']
        self.symbolic = kwargs['symbolic']
        #
        self.solver   = kwargs['solver']
        self.path     = kwargs['path']
        #
        self.log      = kwargs['log']
        self.cnts     = kwargs['cnts']
        self.sha3s    = kwargs['sha3s']
        self.storages = kwargs['storages']
        self.calls    = kwargs['calls']
        self.failed   = kwargs['failed']
        self.error    = kwargs['error']

    def str_cnts(self) -> str:
        return ''.join([f'{x[0]}: {x[1]}\n' for x in sorted(self.cnts.items(), key=lambda x: x[0])])

    def str_solver(self) -> str:
        return '\n'.join([str(cond) for cond in self.solver.assertions()])

    def str_path(self) -> str:
        return ''.join(map(lambda x: '- ' + str(x) + '\n', filter(lambda x: str(x) != 'True', self.path)))

    def __str__(self) -> str:
        return ''.join([
            'PC: '              , str(self.this), ' ', str(self.pc), ' ', str(self.pgm[self.this][self.pc]), '\n',
            str(self.st),
            'Storage:\n'        , ''.join(map(lambda x: '- ' + str(x) + ': ' + str(self.storage[x]) + '\n', self.storage)),
            'Balance:\n'        , ''.join(map(lambda x: '- ' + str(x) + ': ' + str(self.balance[x]) + '\n', self.balance)),
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

    def next_pc(self) -> None:
        self.pc += 1
        while self.pgm[self.this][self.pc] is None:
            self.pc += 1

    def balance_of(self, addr: Word) -> Word:
        if addr not in self.balance:
            self.balance[addr] = f_orig_balance(addr)
        return self.balance[addr]

    def sinit(self, slot: int, keys) -> None:
        if slot not in self.storage[self.this]:
            self.storage[self.this][slot] = {}
        if len(keys) not in self.storage[self.this][slot]:
            if len(keys) == 0:
                if self.symbolic:
                    self.storage[self.this][slot][len(keys)] = BitVec(f'storage_slot_{str(slot)}_{str(len(keys))}', 256)
                else:
                    self.storage[self.this][slot][len(keys)] = con(0)
            else:
                if self.symbolic:
                    self.storage[self.this][slot][len(keys)] = Array(f'storage_slot_{str(slot)}_{str(len(keys))}', BitVecSort(len(keys)*256), BitVecSort(256))
                else:
                    self.storage[self.this][slot][len(keys)] = K(BitVecSort(len(keys)*256), con(0))

    def sload(self, loc: Word) -> Word:
        offsets = self.decode_storage_loc(loc)
        if not len(offsets) > 0: raise ValueError(offsets)
        slot, keys = int(str(offsets[0])), offsets[1:]
        self.sinit(slot, keys)
        if len(keys) == 0:
            return self.storage[self.this][slot][0]
        else:
            return Select(self.storage[self.this][slot][len(keys)], concat(keys))

    def sstore(self, loc: Any, val: Any) -> None:
        offsets = self.decode_storage_loc(loc)
        if not len(offsets) > 0: raise ValueError(offsets)
        slot, keys = int(str(offsets[0])), offsets[1:]
        self.sinit(slot, keys)
        if len(keys) == 0:
            self.storage[self.this][slot][0] = val
        else:
            new_storage_var = Array(f'storage{self.cnt_sstore()}', BitVecSort(len(keys)*256), BitVecSort(256))
            new_storage = Store(self.storage[self.this][slot][len(keys)], concat(keys), val)
            self.solver.add(new_storage_var == new_storage)
            self.storage[self.this][slot][len(keys)] = new_storage_var
            self.storages.append((new_storage_var,new_storage))

    def decode_storage_loc(self, loc: Any) -> Any:
        def normalize(expr: Any) -> Any:
            # Concat(Extract(255, 8, bvadd(x, y)), bvadd(Extract(7, 0, x), Extract(7, 0, y))) => x + y
            if expr.decl().name() == 'concat' and expr.num_args() == 2:
                arg0 = expr.arg(0) # Extract(255, 8, bvadd(x, y))
                arg1 = expr.arg(1) # bvadd(Extract(7, 0, x), Extract(7, 0, y))
                if arg0.decl().name() == 'extract' and arg0.num_args() == 1 and arg0.params() == [255, 8]:
                    arg00 = arg0.arg(0) # bvadd(x, y)
                    if arg00.decl().name() == 'bvadd':
                        x = arg00.arg(0)
                        y = arg00.arg(1)
                        if arg1.decl().name() == 'bvadd' and arg1.num_args() == 2:
                            if arg1.arg(0) == Extract(7, 0, x) and arg1.arg(1) == Extract(7, 0, y):
                                return x + y
            return expr
        loc = normalize(loc)

        if loc.decl().name() == 'sha3_512': # m[k] : hash(k.m)
            args = loc.arg(0)
            offset, base = simplify(Extract(511, 256, args)), simplify(Extract(255, 0, args))
            return self.decode_storage_loc(base) + (offset,con(0))
        elif loc.decl().name() == 'sha3_256': # a[i] : hash(a)+i
            base = loc.arg(0)
            return self.decode_storage_loc(base) + (con(0),)
        elif loc.decl().name() == 'bvadd':
        #   # when len(args) == 2
        #   arg0 = self.decode_storage_loc(loc.arg(0))
        #   arg1 = self.decode_storage_loc(loc.arg(1))
        #   if len(arg0) == 1 and len(arg1) > 1: # i + hash(x)
        #       return arg1[0:-1] + (arg1[-1] + arg0[0],)
        #   elif len(arg0) > 1 and len(arg1) == 1: # hash(x) + i
        #       return arg0[0:-1] + (arg0[-1] + arg1[0],)
        #   elif len(arg0) == 1 and len(arg1) == 1: # i + j
        #       return (arg0[0] + arg1[0],)
        #   else: # hash(x) + hash(y) # ambiguous
        #       raise ValueError(loc)
            # when len(args) >= 2
            args = loc.children()
            if len(args) < 2: raise ValueError(loc)
            args = sorted(map(self.decode_storage_loc, args), key=lambda x: len(x), reverse=True)
            if len(args[1]) > 1: raise ValueError(loc) # only args[0]'s length >= 1, the others must be 1
            return args[0][0:-1] + (reduce(lambda r, x: r + x[0], args[1:], args[0][-1]),)
        elif is_bv_value(loc) and int(str(loc)) in sha3_inv:
            return (con(sha3_inv[int(str(loc))]), con(0))
        elif is_bv(loc):
            return (loc,)
        else:
            raise ValueError(loc)

    def sha3(self) -> None:
        loc: int = self.st.mloc()
        size: int = int(str(self.st.pop())) # size (in bytes) must be concrete
        self.sha3_data(wload(self.st.memory, loc, size), size)

    def sha3_data(self, data: Bytes, size: int) -> None:
        f_sha3 = Function('sha3_'+str(size*8), BitVecSort(size*8), BitVecSort(256))
        sha3 = f_sha3(data)
        sha3_var = BitVec(f'sha3_var{self.cnt_sha3()}', 256)
        self.solver.add(sha3_var == sha3)
        self.solver.add(ULE(sha3_var, con(2**256 - 2**64))) # assume hash values are sufficiently smaller than the uint max
        self.assume_sha3_distinct(sha3_var, sha3)
        if size == 64 or size == 32: # for storage hashed location
            self.st.push(sha3)
        else:
            self.st.push(sha3_var)

    def assume_sha3_distinct(self, sha3_var, sha3) -> None:
        for (v,s) in self.sha3s:
            if s.decl().name() == sha3.decl().name(): # same size
            #   self.solver.add(Implies(sha3_var == v, sha3.arg(0) == s.arg(0)))
                self.solver.add(Implies(sha3.arg(0) != s.arg(0), sha3_var != v))
            else:
                self.solver.add(sha3_var != v)
        self.solver.add(sha3_var != con(0))
        self.sha3s.append((sha3_var, sha3))

    def cnt_call(self) -> int:
        return self.cnts[EVM.CALL] + self.cnts[EVM.STATICCALL]
    def cnt_sstore(self) -> int:
        return self.cnts[EVM.SSTORE]
    def cnt_gas(self) -> int:
        return self.cnts[EVM.GAS]
    def cnt_balance(self) -> int:
        return self.cnts[EVM.BALANCE]
    def cnt_sha3(self) -> int:
        return self.cnts[EVM.SHA3]
    def cnt_create(self) -> int:
        return self.cnts[EVM.CREATE]

    def returndatasize(self) -> int:
        if self.output is None:
            return 0
        else:
            size: int = self.output.size()
            if not size % 8 == 0: raise ValueError(size)
            return int(size / 8)

    def read_code(self, idx: int) -> Byte:
        if idx < len(self.code[self.this]):
            return self.code[self.this][idx]
        else:
            return BitVecVal(0, 8)

    def is_jumpdest(self, x: Word) -> bool:
        if not is_bv_value(x): return False
        pc: int = int(str(x))
        if pc < 0 or pc >= len(self.pgm[self.this]): return False
        if self.pgm[self.this][pc] is None: return False
        opcode = self.pgm[self.this][pc].op[0]
        return is_bv_value(opcode) and opcode.as_long() == EVM.JUMPDEST

    def jumpi_id(self) -> str:
        return f'{self.pc}:' + ','.join(map(lambda x: str(x) if self.is_jumpdest(x) else '', self.st.stack))

# convert opcode list to opcode map
def ops_to_pgm(ops: List[Opcode]) -> List[Opcode]:
    pgm: List[Opcode] = [None for _ in range(ops[-1].pc + 1)]
    for o in ops:
        pgm[o.pc] = o
    return pgm

#             x  == b   if sort(x) = bool
# int_to_bool(x) == b   if sort(x) = int
def test(x: Word, b: bool) -> Word:
    if is_bool(x):
        if b:
            return x
        else:
            return Not(x)
    elif is_bv(x):
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
    if is_bool(x) and is_bool(y):
        if is_and:
            return And(x, y)
        else:
            return Or(x, y)
    elif is_bv(x) and is_bv(y):
        if is_and:
            return (x & y)
        else:
            return (x | y)
    elif is_bool(x) and is_bv(y):
        return and_or(If(x, con(1), con(0)), y, is_and)
    elif is_bv(x) and is_bool(y):
        return and_or(x, If(y, con(1), con(0)), is_and)
    else:
        raise ValueError(x, y, is_and)

def and_of(x: Word, y: Word) -> Word:
    return and_or(x, y, True)

def or_of(x: Word, y: Word) -> Word:
    return and_or(x, y, False)

def b2i(w: Word) -> Word:
    if is_true(w):
        return con(1)
    if is_false(w):
        return con(0)
    if is_bool(w):
        return If(w, con(1), con(0))
    else:
        return w

def is_power_of_two(x: int) -> bool:
    if x > 0:
        return not (x & (x - 1))
    else:
        return False

class SEVM:
    options: Dict

    def __init__(self, options: Dict) -> None:
        self.options = options

    def div_xy_y(self, w1: Word, w2: Word) -> Word:
        # return the number of bits required to represent the given value. default = 256
        def bitsize(w: Word) -> int:
            if w.decl().name() == 'concat' and is_bv_value(w.arg(0)) and int(str(w.arg(0))) == 0:
                return 256 - w.arg(0).size()
            return 256
        if w1.decl().name() == 'bvmul' and w1.num_args() == 2:
            x = w1.arg(0)
            y = w1.arg(1)
            if w2 == x or w2 == y: # xy/x or xy/y
                size_x = bitsize(x)
                size_y = bitsize(y)
                if size_x + size_y <= 256:
                    if w2 == x: # xy/x == y
                        return y
                    else: # xy/y == x
                        return x
        return None

    def arith(self, op: int, w1: Word, w2: Word) -> Word:
        w1 = b2i(w1)
        w2 = b2i(w2)
        if op == EVM.ADD:
            if self.options.get('add'):
                return w1 + w2
            if is_bv_value(w1) and is_bv_value(w2):
                return w1 + w2
            else:
                return f_add(w1, w2)
        elif op == EVM.SUB:
            if self.options.get('sub'):
                return w1 - w2
            if is_bv_value(w1) and is_bv_value(w2):
                return w1 - w2
            else:
                return f_sub(w1, w2)
        elif op == EVM.MUL:
            if self.options.get('mul'):
                return w1 * w2
            if is_bv_value(w1) and is_bv_value(w2):
                return w1 * w2
            elif is_bv_value(w1):
                i1: int = int(str(w1)) # must be concrete
                if i1 == 0:
                    return con(0)
                elif is_power_of_two(i1):
                    return w2 << int(math.log(i1,2))
                else:
                    return f_mul(w1, w2)
            elif is_bv_value(w2):
                i2: int = int(str(w2)) # must be concrete
                if i2 == 0:
                    return con(0)
                elif is_power_of_two(i2):
                    return w1 << int(math.log(i2,2))
                else:
                    return f_mul(w1, w2)
            else:
                return f_mul(w1, w2)
        elif op == EVM.DIV:
            div_for_overflow_check = self.div_xy_y(w1, w2)
            if div_for_overflow_check is not None: # xy/x or xy/y
                return div_for_overflow_check
            if self.options.get('div'):
                return UDiv(w1, w2) # unsigned div (bvudiv)
            if is_bv_value(w1) and is_bv_value(w2):
                return UDiv(w1, w2)
            elif is_bv_value(w2):
                i2: int = int(str(w2)) # must be concrete
                if i2 == 0:
                    return con(0)
                elif i2 == 1:
                    return w1
                elif is_power_of_two(i2):
                    return LShR(w1, int(math.log(i2,2)))
                elif self.options.get('divByConst'):
                    return UDiv(w1, w2)
                else:
                    return f_div(w1, w2)
            else:
                return f_div(w1, w2)
        elif op == EVM.MOD:
            if is_bv_value(w1) and is_bv_value(w2):
                return URem(w1, w2) # bvurem
            elif is_bv_value(w2):
                i2: int = int(str(w2))
                if i2 == 0 or i2 == 1:
                    return con(0)
                elif is_power_of_two(i2):
                    bitsize = int(math.log(i2,2))
                    return ZeroExt(256-bitsize, Extract(bitsize-1, 0, w1))
                elif self.options.get('modByConst'):
                    return URem(w1, w2)
                else:
                    return f_mod(w1, w2)
            else:
                return f_mod(w1, w2)
        elif op == EVM.SDIV:
            if is_bv_value(w1) and is_bv_value(w2):
                return w1 / w2 # bvsdiv
            else:
                return f_sdiv(w1, w2)
        elif op == EVM.SMOD:
            if is_bv_value(w1) and is_bv_value(w2):
                return SRem(w1, w2) # bvsrem  # vs: w1 % w2 (bvsmod w1 w2)
            else:
                return f_smod(w1, w2)
        elif op == EVM.EXP:
            if is_bv_value(w1) and is_bv_value(w2):
                i1: int = int(str(w1)) # must be concrete
                i2: int = int(str(w2)) # must be concrete
                return con(i1 ** i2)
            elif is_bv_value(w2):
                i2: int = int(str(w2))
                if i2 == 0:
                    return con(1)
                elif i2 == 1:
                    return w1
                elif i2 <= self.options.get('expByConst'):
                    exp = w1
                    for _ in range(i2 - 1):
                        exp = exp * w1
                    return exp
                else:
                    return f_exp(w1, w2)
            else:
                return f_exp(w1, w2)
        else:
            raise ValueError(op)

    def call(self, ex: Exec, op: int, stack: List[Tuple[Exec,int]], step_id: int, out: List[Exec]) -> None:
        gas = ex.st.pop()
        to = ex.st.pop()
        if op == EVM.STATICCALL:
            fund = con(0)
        else:
            fund = ex.st.pop()
        arg_loc: int = ex.st.mloc()
        arg_size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete
        ret_loc: int = ex.st.mloc()
        ret_size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete

        if not arg_size >= 0: raise ValueError(arg_size)
        if not ret_size >= 0: raise ValueError(ret_size)

        ex.balance[ex.this] = self.arith(EVM.SUB, ex.balance_of(ex.this), fund)

        def call_known() -> None:
            calldata = [None] * arg_size
            wextend(ex.st.memory, arg_loc, arg_size)
            wstore_bytes(calldata, 0, arg_size, ex.st.memory[arg_loc:arg_loc+arg_size])

            # execute external calls
            (new_exs, new_steps) = self.run(Exec(
                pgm       = ex.pgm,
                code      = ex.code,
                storage   = ex.storage,
                balance   = ex.balance,
                #
                calldata  = calldata,
                callvalue = fund,
                caller    = ex.this,
                this      = to,
                #
                pc        = 0,
                st        = State(),
                jumpis    = {},
                output    = None,
                symbolic  = ex.symbolic,
                #
                solver    = ex.solver,
                path      = ex.path,
                #
                log       = ex.log,
                cnts      = ex.cnts,
                sha3s     = ex.sha3s,
                storages  = ex.storages,
                calls     = ex.calls,
                failed    = ex.failed,
                error     = ex.error,
            ))

            # process result
            for idx, new_ex in enumerate(new_exs):
                opcode = new_ex.pgm[new_ex.this][new_ex.pc].op[0]

                # restore tx msg
                new_ex.calldata  = ex.calldata
                new_ex.callvalue = ex.callvalue
                new_ex.caller    = ex.caller
                new_ex.this      = ex.this

                # restore vm state
                new_ex.pc = ex.pc
                new_ex.st = deepcopy(ex.st)
                new_ex.jumpis = deepcopy(ex.jumpis)
                # new_ex.output is passed into the caller
                new_ex.symbolic = ex.symbolic

                # set return data (in memory)
                wstore_partial(new_ex.st.memory, ret_loc, 0, min(ret_size, new_ex.returndatasize()), new_ex.output, new_ex.returndatasize())

                # set status code (in stack)
                if is_bv_value(opcode) and opcode.as_long() in [EVM.STOP, EVM.RETURN, EVM.REVERT, EVM.INVALID]:
                    if opcode.as_long() in [EVM.STOP, EVM.RETURN]:
                        new_ex.st.push(con(1))
                    else:
                        new_ex.st.push(con(0))

                    # add to worklist even if it reverted during the external call
                    new_ex.next_pc()
                    stack.append((new_ex, step_id))
                else:
                    # got stuck during external call
                    new_ex.error = str('external call stuck: ' + opcode)
                    out.append(new_ex)

        def call_unknown() -> None:
            # push exit code
            if arg_size > 0:
                arg = wload(ex.st.memory, arg_loc, arg_size)
                f_call = Function('call_'+str(arg_size*8), BitVecSort(256), BitVecSort(256), BitVecSort(256), BitVecSort(256), BitVecSort(arg_size*8), BitVecSort(256))
                exit_code = f_call(con(ex.cnt_call()), gas, to, fund, arg)
            else:
                f_call = Function('call_'+str(arg_size*8), BitVecSort(256), BitVecSort(256), BitVecSort(256), BitVecSort(256),                         BitVecSort(256))
                exit_code = f_call(con(ex.cnt_call()), gas, to, fund)
            exit_code_var = BitVec(f'call{ex.cnt_call()}', 256)
            ex.solver.add(exit_code_var == exit_code)
            ex.st.push(exit_code_var)

            ret = None
            if ret_size > 0: # TODO: handle inconsistent return sizes for unknown functions
                f_ret = Function('ret_'+str(ret_size*8), BitVecSort(256), BitVecSort(ret_size*8))
                ret = f_ret(exit_code_var)

            # TODO: cover other precompiled
            if to == con(1): # ecrecover exit code is always 1
                ex.solver.add(exit_code_var != con(0))

            # vm cheat code
            if to == con(hevm_cheat_code.address):
                ex.solver.add(exit_code_var != con(0))
                # vm.fail()
                if arg == hevm_cheat_code.fail_payload: # BitVecVal(hevm_cheat_code.fail_payload, 800)
                    ex.failed = True
                # vm.assume()
                elif eq(arg.sort(), BitVecSort((4+32)*8)) and simplify(Extract(287, 256, arg)) == hevm_cheat_code.assume_sig:
                    assume_cond = simplify(is_non_zero(Extract(255, 0, arg)))
                    ex.solver.add(assume_cond)
                    ex.path.append(str(assume_cond))
                elif simplify(Extract(arg_size*8-1, arg_size*8-32, arg)) == hevm_cheat_code.get_code_sig:
                    calldata = bytes.fromhex(hex(arg.as_long())[2:])
                    path_len = int.from_bytes(calldata[36:68], 'big')
                    path = calldata[68:68+path_len].decode('utf-8')

                    if ':' in path:
                        [filename, contract_name] = path.split(':')
                        path = 'out/' + filename + '/' + contract_name + '.json'

                    target = self.options['target'].rstrip('/')
                    path = target + '/' + path
                    
                    with open(path) as f:
                        artifact = json.loads(f.read())
                    
                    if artifact['bytecode']['object']:
                        bytecode = artifact['bytecode']['object'].replace('0x', '')
                    else:
                        bytecode = artifact['bytecode'].replace('0x', '')

                    bytecode_len = (len(bytecode) + 1) // 2
                    bytecode_len_enc = hex(bytecode_len).replace('0x', '').rjust(64, '0')

                    bytecode_len_ceil = (bytecode_len + 31) // 32 * 32

                    ret_bytes = '00' * 31 + '20' + bytecode_len_enc + bytecode.ljust(bytecode_len_ceil*2, '0')
                    ret_len = len(ret_bytes) // 2
                    ret_bytes = bytes.fromhex(ret_bytes)

                    ret = BitVecVal(int.from_bytes(ret_bytes, 'big'), ret_len * 8)
                else:
                    # TODO: support other cheat codes
                    ex.error = str('Unsupported cheat code: calldata: ' + str(arg))
                    out.append(ex)
                    return

            # store return value
            if ret_size > 0:
                wstore(ex.st.memory, ret_loc, ret_size, ret)

            # propagate callee's output to caller, which could be None
            ex.output = ret

            ex.calls.append((exit_code_var, exit_code, ex.output))

            ex.next_pc()
            stack.append((ex, step_id))

        # separately handle known / unknown external calls
        if to in ex.pgm:
            call_known()
        else:
            call_unknown()

    def create(self, ex: Exec, stack: List[Tuple[Exec,int]], step_id: int, out: List[Exec]) -> None:
        value: Word = ex.st.pop()
        loc: int = int(str(ex.st.pop()))
        size: int = int(str(ex.st.pop()))

        # contract creation code
        create_hexcode = wload(ex.st.memory, loc, size)
        (create_ops, create_code) = decode(create_hexcode)
        create_pgm = ops_to_pgm(create_ops)

        # new account address
        new_addr = create_address(ex.cnt_create())

        # setup new account
        ex.pgm[new_addr] = create_pgm   # existing pgm must be empty
        ex.code[new_addr] = create_code # existing code must be empty
        ex.storage[new_addr] = {}       # existing storage may not be empty and reset here
        ex.balance[new_addr] = f_orig_balance(new_addr)

        # transfer value
        ex.solver.add(UGE(ex.balance_of(ex.this), value)) # assume balance is enough; otherwise ignore this path
        ex.balance[ex.this] = self.arith(EVM.SUB, ex.balance_of(ex.this), value)
        ex.balance[new_addr] = self.arith(EVM.ADD, ex.balance_of(new_addr), value)

        # execute contract creation code
        (new_exs, new_steps) = self.run(Exec(
            pgm       = ex.pgm,
            code      = ex.code,
            storage   = ex.storage,
            balance   = ex.balance,
            #
            calldata  = [],
            callvalue = value,
            caller    = ex.this,
            this      = new_addr,
            #
            pc        = 0,
            st        = State(),
            jumpis    = {},
            output    = None,
            symbolic  = False,
            #
            solver    = ex.solver,
            path      = ex.path,
            #
            log       = ex.log,
            cnts      = ex.cnts,
            sha3s     = ex.sha3s,
            storages  = ex.storages,
            calls     = ex.calls,
            failed    = ex.failed,
            error     = ex.error,
        ))

        # process result
        for idx, new_ex in enumerate(new_exs):
            # sanity checks
            if new_ex.failed: raise ValueError(new_ex)

            opcode = new_ex.pgm[new_ex.this][new_ex.pc].op[0]
            if is_bv_value(opcode) and opcode.as_long() in [EVM.STOP, EVM.RETURN]:
                # new contract code
                new_hexcode = new_ex.output
                (new_ops, new_code) = decode(new_hexcode)
                new_pgm = ops_to_pgm(new_ops)

                # set new contract code
                new_ex.pgm[new_addr] = new_pgm
                new_ex.code[new_addr] = new_code

                # restore tx msg
                new_ex.calldata  = ex.calldata
                new_ex.callvalue = ex.callvalue
                new_ex.caller    = ex.caller
                new_ex.this      = ex.this

                # restore vm state
                new_ex.pc = ex.pc
                new_ex.st = deepcopy(ex.st)
                new_ex.jumpis = deepcopy(ex.jumpis)
                new_ex.output = None # output is reset, not restored
                new_ex.symbolic = ex.symbolic

                # push new address to stack
                new_ex.st.push(new_addr)

                # add to worklist
                new_ex.next_pc()
                stack.append((new_ex, step_id))
            else:
                # creation failed
                out.append(new_ex)

    def jumpi(self, ex: Exec, stack: List[Tuple[Exec,int]], step_id: int) -> None:
        jid = ex.jumpi_id()

        source: int = ex.pc
        target: int = int(str(ex.st.pop())) # target must be concrete
        cond: Word = ex.st.pop()

        visited = ex.jumpis.get(jid, {True: 0, False: 0})

        new_ex_true = None
        new_ex_false = None

        ex.solver.push()
        cond_true = simplify(is_non_zero(cond))
        ex.solver.add(cond_true)
        if ex.solver.check() != unsat: # jump
            new_ex_true = self.create_branch(ex, str(cond_true), target)
        ex.solver.pop()

        cond_false = simplify(is_zero(cond))
        ex.solver.add(cond_false)
        if ex.solver.check() != unsat:
            ex.path.append(str(cond_false))
            ex.next_pc()
            new_ex_false = ex

        if new_ex_true and new_ex_false: # for loop unrolling
            if visited[True] < self.options['max_loop']: # or source < target:
                new_ex_true.jumpis[jid] = {True: visited[True] + 1, False: visited[False]}
                stack.append((new_ex_true, step_id))
            if visited[False] < self.options['max_loop']: # or source < target:
                new_ex_false.jumpis[jid] = {True: visited[True], False: visited[False] + 1}
                stack.append((new_ex_false, step_id))
        elif new_ex_true: # for constant-bounded loops
            stack.append((new_ex_true, step_id))
        elif new_ex_false:
            stack.append((new_ex_false, step_id))
        else:
            pass # this may happen if the previous path condition was considered unknown but turns out to be unsat later

    def jump(self, ex: Exec, stack: List[Tuple[Exec,int]], step_id: int) -> None:
        dst = ex.st.pop()

        # if dst is concrete, just jump
        if is_bv_value(dst):
            ex.pc = int(str(dst))
            stack.append((ex, step_id))

        # otherwise, create a new execution for feasible targets
        elif self.options['sym_jump']:
            for target in valid_jump_destinations(ex.pgm[ex.this]):
                ex.solver.push()
                target_reachable = simplify(dst == target)
                ex.solver.add(target_reachable)
                if ex.solver.check() != unsat: # jump
                    if self.options.get('debug'):
                        print(f"we can jump to {target} with model {ex.solver.model()}")
                    new_ex = self.create_branch(ex, str(target_reachable), target)
                    stack.append((new_ex, step_id))
                ex.solver.pop()

        else:
            raise ValueError(dst)

    def create_branch(self, ex: Exec, cond: str, target: int) -> Exec:
        new_solver = SolverFor('QF_AUFBV')
        new_solver.set(timeout=self.options['timeout'])
        new_solver.add(ex.solver.assertions())
        new_path = deepcopy(ex.path)
        new_path.append(cond)
        new_ex = Exec(
            pgm      = ex.pgm.copy(), # shallow copy for potential new contract creation; existing code doesn't change
            code     = ex.code.copy(), # shallow copy
            storage  = deepcopy(ex.storage),
            balance  = deepcopy(ex.balance),
            #
            calldata = ex.calldata,
            callvalue= ex.callvalue,
            caller   = ex.caller,
            this     = ex.this,
            #
            pc       = target,
            st       = deepcopy(ex.st),
            jumpis   = deepcopy(ex.jumpis),
            output   = deepcopy(ex.output),
            symbolic = ex.symbolic,
            #
            solver   = new_solver,
            path     = new_path,
            #
            log      = deepcopy(ex.log),
            cnts     = deepcopy(ex.cnts),
            sha3s    = deepcopy(ex.sha3s),
            storages = deepcopy(ex.storages),
            calls    = deepcopy(ex.calls),
            failed   = ex.failed,
            error    = ex.error,
        )
        return new_ex

    def run(self, ex0: Exec) -> Tuple[List[Exec], Steps]:
        out: List[Exec] = []
        steps: Steps = {}
        step_id: int = 0

        stack: List[Tuple[Exec,int]] = [(ex0, 0)]
        while stack:
            try:
                if 'max_width' in self.options and len(out) >= self.options['max_width']: break

                (ex, prev_step_id) = stack.pop()
                step_id += 1

                o = ex.pgm[ex.this][ex.pc]
                opcode = o.op[0]
                if is_bv_value(opcode):
                    opcode = int(str(opcode))
                else:
                    out.append(ex)
                    continue
                ex.cnts[opcode] += 1

                if 'max_depth' in self.options and sum(ex.cnts.values()) > self.options['max_depth']:
                    continue

                if self.options.get('log'):
                    if opcode == EVM.JUMPI:
                        steps[step_id] = {'parent': prev_step_id, 'exec': str(ex)}
                #   elif opcode == EVM.CALL:
                #       steps[step_id] = {'parent': prev_step_id, 'exec': str(ex) + ex.st.str_memory() + '\n'}
                    else:
                    #   steps[step_id] = {'parent': prev_step_id, 'exec': ex.summary()}
                        steps[step_id] = {'parent': prev_step_id, 'exec': str(ex)}
                    if self.options.get('verbose', 0) >= 3:
                        print(ex)

                if opcode == EVM.STOP:
                    ex.output = None
                    out.append(ex)
                    continue

                elif opcode == EVM.REVERT:
                    ex.output = ex.st.ret()
                    out.append(ex)
                    continue

                elif opcode == EVM.RETURN:
                    ex.output = ex.st.ret()
                    out.append(ex)
                    continue

                elif opcode == EVM.JUMPI:
                    self.jumpi(ex, stack, step_id)
                    continue

                elif opcode == EVM.JUMP:
                    self.jump(ex, stack, step_id)
                    continue

                elif opcode == EVM.JUMPDEST:
                    pass

                elif EVM.ADD <= opcode <= EVM.SMOD: # ADD MUL SUB DIV SDIV MOD SMOD
                    ex.st.push(self.arith(opcode, ex.st.pop(), ex.st.pop()))

                elif opcode == EVM.EXP:
                    ex.st.push(self.arith(opcode, ex.st.pop(), ex.st.pop()))

                elif opcode == EVM.LT:
                    w1 = b2i(ex.st.pop())
                    w2 = b2i(ex.st.pop())
                    ex.st.push(ULT(w1, w2)) # bvult
                elif opcode == EVM.GT:
                    w1 = b2i(ex.st.pop())
                    w2 = b2i(ex.st.pop())
                    ex.st.push(UGT(w1, w2)) # bvugt
                elif opcode == EVM.SLT:
                    w1 = b2i(ex.st.pop())
                    w2 = b2i(ex.st.pop())
                    ex.st.push(w1 < w2) # bvslt
                elif opcode == EVM.SGT:
                    w1 = b2i(ex.st.pop())
                    w2 = b2i(ex.st.pop())
                    ex.st.push(w1 > w2) # bvsgt

                elif opcode == EVM.EQ:
                    w1 = ex.st.pop()
                    w2 = ex.st.pop()
                    if eq(w1.sort(), w2.sort()):
                        ex.st.push(w1 == w2)
                    else:
                        if is_bool(w1):
                            if not is_bv(w2): raise ValueError(w2)
                            ex.st.push(If(w1, con(1), con(0)) == w2)
                        else:
                            if not is_bv(w1): raise ValueError(w1)
                            if not is_bool(w2): raise ValueError(w2)
                            ex.st.push(w1 == If(w2, con(1), con(0)))
                elif opcode == EVM.ISZERO:
                    ex.st.push(is_zero(ex.st.pop()))

                elif opcode == EVM.AND:
                    ex.st.push(and_of(ex.st.pop(), ex.st.pop()))
                elif opcode == EVM.OR:
                    ex.st.push(or_of(ex.st.pop(), ex.st.pop()))
                elif opcode == EVM.NOT:
                    ex.st.push(~ ex.st.pop()) # bvnot
                elif opcode == EVM.SHL:
                    w = ex.st.pop()
                    ex.st.push(b2i(ex.st.pop()) << b2i(w)) # bvshl
                elif opcode == EVM.SAR:
                    w = ex.st.pop()
                    ex.st.push(ex.st.pop() >> w) # bvashr
                elif opcode == EVM.SHR:
                    w = ex.st.pop()
                    ex.st.push(LShR(ex.st.pop(), w)) # bvlshr

                elif opcode == EVM.SIGNEXTEND:
                    w = ex.st.pop()
                    if not is_bv_value(w): raise ValueError(w)

                    w = int(str(w))
                    if w <= 30: # if w == 31, result is SignExt(0, value) == value
                        bl = (w + 1) * 8
                        ex.st.push(SignExt(256 - bl, Extract(bl - 1, 0, ex.st.pop())))

                elif opcode == EVM.XOR:
                    ex.st.push(ex.st.pop() ^ ex.st.pop()) # bvxor

                elif opcode == EVM.CALLDATALOAD:
                    if ex.calldata is None:
                        ex.st.push(f_calldataload(ex.st.pop()))
                    else:
                        offset: int = int(str(ex.st.pop()))
                        ex.st.push(Concat((ex.calldata + [BitVecVal(0, 8)] * 32)[offset:offset+32]))
                    #   try:
                    #       offset: int = int(str(ex.st.pop()))
                    #       ex.st.push(Concat(ex.calldata[offset:offset+32]))
                    #   except:
                    #       ex.st.push(f_calldataload(ex.st.pop()))
                elif opcode == EVM.CALLDATASIZE:
                    if ex.calldata is None:
                        ex.st.push(f_calldatasize())
                    else:
                        ex.st.push(con(len(ex.calldata)))
                elif opcode == EVM.CALLVALUE:
                    ex.st.push(ex.callvalue)
                elif opcode == EVM.CALLER:
                    ex.st.push(ex.caller)
                elif opcode == EVM.ORIGIN:
                    ex.st.push(f_origin())
                    ex.solver.add(Extract(255, 160, f_origin()) == BitVecVal(0, 96))
                elif opcode == EVM.ADDRESS:
                    ex.st.push(ex.this)
                elif opcode == EVM.COINBASE:
                    ex.st.push(f_coinbase())
                    ex.solver.add(Extract(255, 160, f_coinbase()) == BitVecVal(0, 96))
                elif opcode == EVM.EXTCODESIZE:
                    address = ex.st.pop()
                    if address in ex.code:
                        codesize = con(len(ex.code[address]))
                    else:
                        codesize = f_extcodesize(address)
                        if address == con(hevm_cheat_code.address):
                            ex.solver.add(codesize > 0)
                    ex.st.push(codesize)
                elif opcode == EVM.EXTCODEHASH:
                    ex.st.push(f_extcodehash(ex.st.pop()))
                elif opcode == EVM.CODESIZE:
                    ex.st.push(con(len(ex.code[ex.this])))
                elif opcode == EVM.GAS:
                    ex.st.push(f_gas(con(ex.cnt_gas())))
                elif opcode == EVM.GASPRICE:
                    ex.st.push(f_gasprice())
                elif opcode == EVM.TIMESTAMP:
                    ex.st.push(f_timestamp())
                elif opcode == EVM.NUMBER:
                    ex.st.push(f_blocknumber())
                elif opcode == EVM.DIFFICULTY:
                    ex.st.push(f_difficulty())
                elif opcode == EVM.GASLIMIT:
                    ex.st.push(f_gaslimit())

                elif opcode == EVM.CHAINID:
                #   ex.st.push(f_chainid())
                    ex.st.push(con(1)) # for ethereum

                elif opcode == EVM.BLOCKHASH:
                    ex.st.push(f_blockhash(ex.st.pop()))

                elif opcode == EVM.BALANCE:
                    ex.st.push(ex.balance_of(ex.st.pop()))
                elif opcode == EVM.SELFBALANCE:
                    ex.st.push(ex.balance_of(ex.this))

                elif opcode == EVM.CALL or opcode == EVM.STATICCALL:
                    self.call(ex, opcode, stack, step_id, out)
                    continue

                elif opcode == EVM.SHA3:
                    ex.sha3()

                elif opcode == EVM.CREATE:
                    self.create(ex, stack, step_id, out)
                    continue

                elif opcode == EVM.POP:
                    ex.st.pop()
                elif opcode == EVM.MLOAD:
                    ex.st.mload()
                elif opcode == EVM.MSTORE:
                    ex.st.mstore(True)
                elif opcode == EVM.MSTORE8:
                    ex.st.mstore(False)

                elif opcode == EVM.MSIZE:
                    size: int = len(ex.st.memory)
                    size = ((size + 31) // 32) * 32 # round up to the next multiple of 32
                    ex.st.push(con(size))

                elif opcode == EVM.SLOAD:
                    ex.st.push(ex.sload(ex.st.pop()))
                elif opcode == EVM.SSTORE:
                    ex.sstore(ex.st.pop(), ex.st.pop())

                elif opcode == EVM.RETURNDATASIZE:
                    ex.st.push(con(ex.returndatasize()))
                elif opcode == EVM.RETURNDATACOPY:
                    loc: int = ex.st.mloc()
                    offset: int = int(str(ex.st.pop())) # offset must be concrete
                    size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete
                    wstore_partial(ex.st.memory, loc, offset, size, ex.output, ex.returndatasize())

                elif opcode == EVM.CALLDATACOPY:
                    loc: int = ex.st.mloc()
                    offset: int = int(str(ex.st.pop())) # offset must be concrete
                    size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete
                    if size > 0:
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

                elif opcode == EVM.CODECOPY:
                    loc: int = ex.st.mloc()
                    pc: int = int(str(ex.st.pop())) # pc must be concrete
                    size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete
                    wextend(ex.st.memory, loc, size)
                    for i in range(size):
                        ex.st.memory[loc + i] = ex.read_code(pc + i)

                elif opcode == EVM.BYTE:
                    idx: int = int(str(ex.st.pop())) # index must be concrete
                    if idx < 0: raise ValueError(idx)
                    w = ex.st.pop()
                    if idx >= 32:
                        ex.st.push(con(0))
                    else:
                        ex.st.push(ZeroExt(248, Extract((31-idx)*8+7, (31-idx)*8, w)))

                elif EVM.LOG0 <= opcode <= EVM.LOG4:
                    num_keys: int = opcode - EVM.LOG0
                    loc: int = ex.st.mloc()
                    size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete
                    keys = []
                    for _ in range(num_keys):
                        keys.append(ex.st.pop())
                    ex.log.append((keys, wload(ex.st.memory, loc, size) if size > 0 else None))

                elif EVM.PUSH1 <= opcode <= EVM.PUSH32:
                    if is_bv_value(o.op[1]):
                        val = int(str(o.op[1]))
                        if opcode == EVM.PUSH32 and val in sha3_inv: # restore precomputed hashes
                            ex.sha3_data(con(sha3_inv[val]), 32)
                        else:
                            ex.st.push(con(val))
                    else:
                        if opcode == EVM.PUSH32:
                            ex.st.push(o.op[1])
                        else:
                            ex.st.push(ZeroExt((EVM.PUSH32 - opcode)*8, o.op[1]))
                elif EVM.DUP1 <= opcode <= EVM.DUP16:
                    ex.st.dup(opcode - EVM.DUP1 + 1)
                elif EVM.SWAP1 <= opcode <= EVM.SWAP16:
                    ex.st.swap(opcode - EVM.SWAP1 + 1)

                else:
                    out.append(ex)
                    continue

                ex.next_pc()
                stack.append((ex, step_id))

            except Exception as err:
                if self.options['debug']:
                    print(ex)
                raise

        return (out, steps)

    def mk_exec(
        self,
        #
        pgm,
        code,
        storage,
        balance,
        #
        calldata,
        callvalue,
        caller,
        this,
        #
    #   pc,
    #   st,
    #   jumpis,
    #   output,
        symbolic,
        #
        solver,
    #   path,
        #
    #   log,
    #   cnts,
    #   sha3s,
    #   storages,
    #   calls,
    #   failed,
    #   error,
    ) -> Exec:
        return Exec(
            pgm      = pgm,
            code     = code,
            storage  = storage,
            balance  = balance,
            #
            calldata = calldata,
            callvalue= callvalue,
            caller   = caller,
            this     = this,
            #
            pc       = 0,
            st       = State(),
            jumpis   = {},
            output   = None,
            symbolic = symbolic,
            #
            solver   = solver,
            path     = [],
            #
            log      = [],
            cnts     = defaultdict(int),
            sha3s    = [],
            storages = [],
            calls    = [],
            failed   = False,
            error    = '',
        )
