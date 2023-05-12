# SPDX-License-Identifier: AGPL-3.0

from typing import List, Tuple, Any

from z3 import *
from .utils import EVM, str_opcode

class Opcode:
    pc: int
    op: List[Any] # opcode + argument (optional)

    def __init__(self, pc, op) -> None:
        self.pc = pc
        self.op = op

    def __str__(self) -> str:
        ret = mnemonic(self.op[0])
        if len(self.op) > 1:
            ret += ' ' + str(self.op[1])
        return ret

    def __repr__(self) -> str:
        m = mnemonic(self.op[0])
        return f'Opcode(pc={self.pc}, op={" ".join([m] + [str(x) for x in self.op[1:]])})'


def mnemonic(opcode) -> str:
    if is_bv_value(opcode):
        opcode = opcode.as_long()
        return str_opcode.get(opcode, hex(opcode))
    else:
        return str(opcode)

def concat(args):
    if len(args) > 1:
        return Concat(args)
    else:
        return args[0]

# Decode ByteCodes to Opcodes
def decode(hexcode: BitVecRef) -> Tuple[List[Opcode], List[Any]]:
    bitsize: int = hexcode.size()
    if bitsize % 8 != 0: raise ValueError(hexcode)
    code: List[Any] = [ simplify(Extract(bitsize-1 - i*8, bitsize - (i+1)*8, hexcode)) for i in range(bitsize // 8) ]
    args: List[Any] = []
    ops: List[Opcode] = []
    pushcnt: int = 0
    cnt: int = -1
    for item in code:
        cnt += 1
        if pushcnt > 0:
            args.append(item)
            pushcnt -= 1
            if pushcnt == 0:
                ops[-1].op.append(simplify(concat(args)))
                args = []
        else:
            ops.append(Opcode(cnt, [item]))
            if is_bv_value(item):
                hx = int(str(item))
                if EVM.PUSH1 <= hx <= EVM.PUSH32:
                    pushcnt = hx - EVM.PUSH1 + 1
    if args: # args is not empty
        ops[-1].op.append(f'ERROR {str(simplify(concat(args)))} ({pushcnt} bytes missed)')
    return (ops, code)
