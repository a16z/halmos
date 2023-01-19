# SPDX-License-Identifier: AGPL-3.0

import math

from copy import deepcopy
from collections import defaultdict
from typing import List, Dict, Tuple, Any

from z3 import *
from .byte2op import SrcMap, Opcode, decode
from .utils import groupby_gas, color_good, color_warn, hevm_cheat_code

Word = Any # z3 expression (including constants)
Byte = Any # z3 expression (including constants)

Steps = Dict[int,Dict[str,Any]] # execution tree

# symbolic states
f_calldataload = Function('calldataload', BitVecSort(256), BitVecSort(256)) # index
f_calldatasize = Function('calldatasize', BitVecSort(256))
f_callvalue    = Function('callvalue'   , BitVecSort(256))
f_caller       = Function('caller'      , BitVecSort(256))
f_origin       = Function('origin'      , BitVecSort(256))
f_address      = Function('address'     , BitVecSort(256))
f_coinbase     = Function('coinbase'    , BitVecSort(256))
f_extcodesize  = Function('extcodesize' , BitVecSort(256), BitVecSort(256)) # target address
f_gas          = Function('gas'         , BitVecSort(256), BitVecSort(256)) # cnt
f_timestamp    = Function('timestamp'   , BitVecSort(256))
f_chainid      = Function('chainid'     , BitVecSort(256))
f_balance      = Function('balance'     , BitVecSort(256), BitVecSort(256), BitVecSort(256)) # target address, cnt

# uninterpreted arithmetic
f_xor  = Function('evm_xor' , BitVecSort(256), BitVecSort(256), BitVecSort(256))
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

class Exec: # an execution path
    # program
    pgm: List[Opcode] # opcode map: pc -> opcode
    code: List[str] # opcode sequence
    calldata: List[Byte]
    # state
    pc: int
    st: State # stack and memory
    storage: Dict[int,Any] # storage slot -> value
    balance: Any
    output: Any # returndata
    # path
    solver: Solver
    path: List[Any] # path conditions
    # logs
    log: List[Tuple[List[Word], Any]] # event logs emitted
    cnts: Dict[str,int] # opcode -> frequency
    sha3s: List[Tuple[Word,Word]] # sha3 hashes generated
    storages: List[Tuple[Any,Any]] # storage updates
    calls: List[Any] # external calls
    jumps: List[Dict[str,int]]
    failed: bool

    def __init__(self, **kwargs) -> None:
        self.pgm      = kwargs['pgm']
        self.code     = kwargs['code']
        self.calldata = kwargs['calldata']
        #
        self.pc       = kwargs['pc']
        self.st       = kwargs['st']
        self.storage  = kwargs['storage']
        self.balance  = kwargs['balance']
        self.output   = kwargs['output']
        #
        self.solver   = kwargs['solver']
        self.path     = kwargs['path']
        #
        self.log      = kwargs['log']
        self.cnts     = kwargs['cnts']
        self.sha3s    = kwargs['sha3s']
        self.storages = kwargs['storages']
        self.calls    = kwargs['calls']
        self.jumps    = kwargs['jumps']
        self.failed   = kwargs['failed']

    def str_cnts(self) -> str:
        cnts = groupby_gas(self.cnts)
        return ''.join([f'{x[0]}: {x[1]}\n' for x in sorted(cnts.items(), key=lambda x: x[0])])

    def str_solver(self) -> str:
        return '\n'.join([str(cond) for cond in self.solver.assertions()])

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
            self.solver.add(new_storage_var == new_storage)
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
        self.solver.add(sha3_var == sha3)
        self.assume_sha3_distinct(sha3_var, sha3)
        if size == 64: # for storage hashed location
            self.st.push(sha3)
        else:
            self.st.push(sha3_var)

    def assume_sha3_distinct(self, sha3_var, sha3):
        for (v,s) in self.sha3s:
            if s.decl().name() == sha3.decl().name(): # same size
            #   self.solver.add(Implies(sha3_var == v, sha3.arg(0) == s.arg(0)))
                self.solver.add(Implies(sha3.arg(0) != s.arg(0), sha3_var != v))
            else:
                self.solver.add(sha3_var != v)
        self.solver.add(sha3_var != con(0))
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

    def returndatasize(self) -> int:
        if self.output is None:
            return 0
        else:
            size: int = self.output.sort().size()
            if not size % 8 == 0: raise ValueError(size)
            return int(size / 8)

    def read_code(self, idx: int) -> str:
        if idx < len(self.code):
            return self.code[idx]
        else:
            return '00'

# convert opcode list to opcode map
def ops_to_pgm(ops: List[Opcode]) -> List[Opcode]:
    pgm: List[Opcode] = [None for _ in range(ops[-1].pc + 1)]
    for o in ops:
        pgm[o.pc] = o
    return pgm

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

class SEVM:
    options: Dict

    def __init__(self, options: Dict) -> None:
        self.options = options

    def arith(self, op: str, w1: Word, w2: Word) -> Word:
        w1 = b2i(w1)
        w2 = b2i(w2)
        if op == 'ADD':
            if self.options.get('add'):
                return w1 + w2
            if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
                return w1 + w2
            else:
                return f_add(w1, w2)
        elif op == 'SUB':
            if self.options.get('sub'):
                return w1 - w2
            if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
                return w1 - w2
            else:
                return f_sub(w1, w2)
        elif op == 'MUL':
            if self.options.get('mul'):
                return w1 * w2
            if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
                return w1 * w2
            elif w1.decl().name() == 'bv':
                i1: int = int(str(w1)) # must be concrete
                if i1 == 0:
                    return con(0)
                elif is_power_of_two(i1):
                    return w2 << int(math.log(i1,2))
                else:
                    return f_mul(w1, w2)
            elif w2.decl().name() == 'bv':
                i2: int = int(str(w2)) # must be concrete
                if i2 == 0:
                    return con(0)
                elif is_power_of_two(i2):
                    return w1 << int(math.log(i2,2))
                else:
                    return f_mul(w1, w2)
            else:
                return f_mul(w1, w2)
        elif op == 'DIV':
            if self.options.get('div'):
                return UDiv(w1, w2) # unsigned div (bvdiv)
            if w1.decl().name() == 'bv' and w2.decl().name() == 'bv':
                return UDiv(w1, w2)
            elif w2.decl().name() == 'bv':
                i2: int = int(str(w2)) # must be concrete
                if i2 == 0:
                    return con(0)
                elif is_power_of_two(i2):
                    return UDiv(w1, w2)
                else:
                    return f_div(w1, w2)
            else:
                return f_div(w1, w2)
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

    def call(self, ex: Exec, static: bool) -> None:
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

        ex.balance = self.arith('SUB', ex.balance, fund)

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

    def jumpi(self, ex: Exec, stack: List[Exec], step_id: int) -> None:
        source: int = ex.pc
        target: int = int(str(ex.st.pop())) # target must be concrete
        cond: Word = ex.st.pop()

        visited = ex.jumps[-1]['cnt'].get(source, {True: 0, False: 0})

        new_ex_true = None
        new_ex_false = None

        ex.solver.push()
        cond_true = simplify(is_non_zero(cond))
        ex.solver.add(cond_true)
        if ex.solver.check() != unsat: # jump
            new_solver = SolverFor('QF_AUFBV')
            new_solver.set(timeout=self.options['timeout'])
            new_solver.add(ex.solver.assertions())
            new_path = deepcopy(ex.path)
            new_path.append(str(cond_true))
            new_ex_true = Exec(
                pgm      = ex.pgm,
                code     = ex.code,
                calldata = ex.calldata,
                #
                pc       = target,
                st       = deepcopy(ex.st),
                storage  = deepcopy(ex.storage),
                balance  = deepcopy(ex.balance),
                output   = deepcopy(ex.output),
                #
                solver   = new_solver,
                path     = new_path,
                #
                log      = deepcopy(ex.log),
                cnts     = deepcopy(ex.cnts),
                sha3s    = deepcopy(ex.sha3s),
                storages = deepcopy(ex.storages),
                calls    = deepcopy(ex.calls),
                jumps    = deepcopy(ex.jumps),
                failed   = ex.failed,
            )
        ex.solver.pop()

        cond_false = simplify(is_zero(cond))
        ex.solver.add(cond_false)
        if ex.solver.check() != unsat:
            ex.path.append(str(cond_false))
            ex.next_pc()
            new_ex_false = ex

        if new_ex_true and new_ex_false: # for loop unrolling
            if visited[True] < self.options['max_loop']:
                new_ex_true.jumps[-1]['cnt'][source] = {True: visited[True] + 1, False: visited[False]}
                stack.append((new_ex_true, step_id))
            if visited[False] < self.options['max_loop']:
                new_ex_false.jumps[-1]['cnt'][source] = {True: visited[True], False: visited[False] + 1}
                stack.append((new_ex_false, step_id))
        elif new_ex_true: # for constant-bounded loops
            stack.append((new_ex_true, step_id))
        elif new_ex_false:
            stack.append((new_ex_false, step_id))
        else:
            pass # this may happen if the previous path condition was considered unknown but turns out to be unsat later

    def jump(self, ex: Exec, sm: SrcMap, src: int, dst: int) -> bool:
        jmp = {'src': src, 'dst': dst, 'jmp': sm.jump, 'cnt': {}}

        if sm.jump == 'i': # function call
            ex.jumps.append(jmp)
            return True

        if sm.jump == 'o': # function return
            for i in reversed(range(1, len(ex.jumps))):
                if ex.jumps[i]['jmp'] == 'i':
                    if not ex.jumps[i]['src'] + 1 == dst:
                        if self.options.get('debug'):
                            print('warn: unmatched jumps', ex.jumps[i]['src'], dst)
                    ex.jumps = ex.jumps[:i]
                    return True
            if self.options.get('debug'):
                print('warn: unmatched jumps', jmp)

        return True

    def run(self, ex0: Exec) -> Tuple[List[Exec], Steps]:
        out: List[Exec] = []
        steps: Steps = {}
        step_id: int = 0

        stack: List[Tuple[Exec,int]] = [(ex0, 0)]
        while stack:
            if 'max_width' in self.options and len(out) >= self.options['max_width']: break

            (ex, prev_step_id) = stack.pop()
            step_id += 1

            o = ex.pgm[ex.pc]
            ex.cnts[o.op[0]] += 1

            if 'max_depth' in self.options and sum(ex.cnts.values()) > self.options['max_depth']:
                continue

            if self.options.get('log'):
                if o.op[0] == 'JUMPI':
                    steps[step_id] = {'parent': prev_step_id, 'exec': str(ex)}
            #   elif o.op[0] == 'CALL':
            #       steps[step_id] = {'parent': prev_step_id, 'exec': str(ex) + ex.st.str_memory() + '\n'}
                else:
                    steps[step_id] = {'parent': prev_step_id, 'exec': ex.summary()}
                #   steps[step_id] = {'parent': prev_step_id, 'exec': str(ex)}
                if self.options.get('verbose', 0) >= 3:
                    print(ex)

            if o.op[0] == 'STOP':
                ex.output = None
                out.append(ex)
                if self.options.get('debug') and len(ex.jumps) != 1: print(color_warn('Warning: loop unrolling might be incomplete'), ex.jumps)
                continue

            elif o.op[0] == 'REVERT':
                ex.output = ex.st.ret()
                out.append(ex)
                continue

            elif o.op[0] == 'RETURN':
                ex.output = ex.st.ret()
                out.append(ex)
                if self.options.get('debug') and len(ex.jumps) != 1: print(color_warn('Warning: loop unrolling might be incomplete'), ex.jumps)
                continue

            elif o.op[0] == 'JUMPI':
                self.jumpi(ex, stack, step_id)
                continue

            elif o.op[0] == 'JUMP':
                source: int = ex.pc
                target: int = int(str(ex.st.pop())) # target must be concrete
                ex.pc = target
                if not self.options.get('srcmap') or self.jump(ex, o.sm, source, target):
                    stack.append((ex, step_id))
                continue

            elif o.op[0] == 'JUMPDEST':
                pass

            elif int('01', 16) <= int(o.hx, 16) <= int('07', 16): # ADD MUL SUB DIV SDIV MOD SMOD
                ex.st.push(self.arith(o.op[0], ex.st.pop(), ex.st.pop()))

            elif o.op[0] == 'EXP':
                ex.st.push(self.arith(o.op[0], ex.st.pop(), ex.st.pop()))

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
                ex.solver.add(Extract(255, 160, f_caller()) == BitVecVal(0, 96))
            elif o.op[0] == 'ORIGIN':
                ex.st.push(f_origin())
                ex.solver.add(Extract(255, 160, f_origin()) == BitVecVal(0, 96))
            elif o.op[0] == 'ADDRESS':
                ex.st.push(f_address())
                ex.solver.add(Extract(255, 160, f_address()) == BitVecVal(0, 96))
            elif o.op[0] == 'COINBASE':
                ex.st.push(f_coinbase())
                ex.solver.add(Extract(255, 160, f_coinbase()) == BitVecVal(0, 96))
            elif o.op[0] == 'EXTCODESIZE':
                address = ex.st.pop()
                codesize = f_extcodesize(address)
                ex.st.push(codesize)
                if address == con(hevm_cheat_code.address):
                    ex.solver.add(codesize > 0)
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
                self.call(ex, False)
            elif o.op[0] == 'STATICCALL':
                self.call(ex, True)

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
                ex.st.push(con(ex.returndatasize()))
            elif o.op[0] == 'RETURNDATACOPY':
                loc: int = ex.st.mloc()
                offset: int = int(str(ex.st.pop())) # offset must be concrete
                size: int = int(str(ex.st.pop())) # size (in bytes) must be concrete
                if size > 0:
                    datasize: int = ex.returndatasize()
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
                    ex.st.memory[loc + i] = BitVecVal(int(ex.read_code(pc + i), 16), 8)

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

    def execute(
        self,
        ops: List[Opcode],
        code: List[str],
        calldata = None,
        #
        storage = {},
        balance: Any = BitVec('balance', 256),
        output: Any = None,
        #
        solver: Solver = SolverFor('QF_AUFBV'),
        path = [],
        #
        log = [],
        cnts: Dict[str,int] = defaultdict(int),
        sha3s = [],
        storages = [],
        calls = [],
        jumps = [{'cnt':{}}], # dummy entry
        failed = False
    ) -> Tuple[List[Exec], Steps]:
        st = State()
        ex = Exec(
            pgm      = ops_to_pgm(ops),
            code     = code,
            calldata = calldata,
            #
            pc       = 0,
            st       = st,
            storage  = storage,
            balance  = balance + f_callvalue(),
            output   = output,
            #
            solver   = solver,
            path     = path,
            #
            log      = log,
            cnts     = cnts,
            sha3s    = sha3s,
            storages = storages,
            calls    = calls,
            jumps    = jumps,
            failed   = failed,
        )
        return self.run(ex)
