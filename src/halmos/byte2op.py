# SPDX-License-Identifier: AGPL-3.0

import sys

from typing import List, Tuple

from .utils import opcodes

class SrcMap:
    text  : str
    jump  : str
    mdepth: int

    def __init__(self, t='', j='', m=0) -> None:
        self.text   = t
        self.jump   = j
        self.mdepth = m

    def __str__(self) -> str:
        return ' '.join([
            self.jump,
            str(self.mdepth),
            self.text,
        ])

class Opcode:
    pc: int
    hx: str         # hex string of byte
    op: List[str]   # opcode + argument (optional)
    sm: SrcMap

    def __init__(self, pc, hx, op) -> None:
        self.pc = pc
        self.hx = hx
        self.op = op
        self.sm = None

    def __str__(self) -> str:
        if self.sm:
            return ' '.join(self.op) + ' ' + str(self.sm)
        else:
            return ' '.join(self.op)


# Decode ByteCodes to Opcodes
def decode(hexcode: str) -> Tuple[List[Opcode], List[str]]:
    if hexcode.startswith('0x'):
        hexcode = hexcode[2:]
    code: List[str] = [hexcode[i:i+2] for i in range(0, len(hexcode), 2)]
    hx: str = ''
    ops: List[Opcode] = []
    pushcnt: int = 0
    cnt: int = -1
    for item in code:
        cnt += 1
        if pushcnt > 0:
            hx += item.lower()
            pushcnt -= 1
            if pushcnt == 0:
                ops[-1].op.append(hx)
                hx = ''
        elif isinstance(item, str) and item.lower() in opcodes:
            ops.append(Opcode(cnt, item.lower(), [opcodes[item.lower()]]))
            if int('60', 16) <= int(item, 16) <= int('7f', 16):
                pushcnt = int(item, 16) - int('60', 16) + 1
        else:
            ops.append(Opcode(cnt, item.lower(), ['ERROR']))
        #   raise ValueError('Invalid opcode', str(item))
    if hx: # hx is not empty
        ops[-1].op.append('ERROR ' + hx + ' (' + str(pushcnt) + ' bytes missed)')
    #   raise ValueError('Not enough push bytes', hx)
    return (ops, code)

def print_opcodes(ops: List[Opcode], mode: str) -> None:
    width: int = len(str(ops[-1].pc)) # the number of digits of the max pc
    for o in ops:
        s: str = '[' + align(o.pc, width) + '] ' + o.hx + ' ' + o.op[0]
        if len(o.op) > 1: # when o.op[0] is PUSH*
            s += ' ' + push_bytes(o.op[1], mode)
        print(s)

def align(cnt: int, width: int) -> str:
    return str(cnt).zfill(width)

def push_bytes(h: str, mode: str) -> str:
    i: str = str(int(h, 16))
    return {
        'hex'     :           '0x' + h  ,
        'int'     : i                   ,
        'int:hex' : i + ':' + '0x' + h  ,
    }[mode]

# usage: <cmd> [int|hex|int:hex]
if __name__ == '__main__':
    mode: str = 'int:hex' if len(sys.argv) < 2 else sys.argv[1]
    hexcode: str = input()
    print_opcodes(decode(hexcode)[0], mode)
