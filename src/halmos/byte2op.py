# SPDX-License-Identifier: AGPL-3.0

import sys

from typing import List, Tuple, Any

from z3 import *
from .utils import opcodes

class Opcode:
    pc: int
    hx: Any
    op: List # opcode + argument (optional)

    def __init__(self, pc, hx, op) -> None:
        self.pc = pc
        self.hx = hx
        self.op = op

    def __str__(self) -> str:
        return ' '.join(map(str, self.op))

def concat(args):
    if len(args) > 1:
        return Concat(args)
    else:
        return args[0]

# Decode ByteCodes to Opcodes
def decode(hexcode) -> Tuple[List[Opcode], List]:
    bitsize: int = hexcode.size()
    if bitsize % 8 != 0: raise ValueError(hexcode)
    code: List = [ simplify(Extract(bitsize-1 - i*8, bitsize - (i+1)*8, hexcode)) for i in range(bitsize // 8) ]
    args: List = []
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
        elif is_bv_value(item) and int(str(item)) in opcodes:
            hx = int(str(item))
            ops.append(Opcode(cnt, item, [opcodes[hx]]))
            if 0x60 <= hx <= 0x7f:
                pushcnt = hx - 0x60 + 1
        else:
            ops.append(Opcode(cnt, item, ['ERROR']))
    if args: # args is not empty
        ops[-1].op.append(f'ERROR {str(simplify(concat(args)))} ({pushcnt} bytes missed)')
    return (ops, code)
