# SPDX-License-Identifier: AGPL-3.0

import sys

from typing import List, Dict, Tuple

opcodes : Dict[str, str] = {
    '00' : 'STOP',
    '01' : 'ADD',
    '02' : 'MUL',
    '03' : 'SUB',
    '04' : 'DIV',
    '05' : 'SDIV',
    '06' : 'MOD',
    '07' : 'SMOD',
    '08' : 'ADDMOD',
    '09' : 'MULMOD',
    '0a' : 'EXP',
    '0b' : 'SIGNEXTEND',
    '10' : 'LT',
    '11' : 'GT',
    '12' : 'SLT',
    '13' : 'SGT',
    '14' : 'EQ',
    '15' : 'ISZERO',
    '16' : 'AND',
    '17' : 'OR',
    '18' : 'XOR',
    '19' : 'NOT',
    '1a' : 'BYTE',
    '1b' : 'SHL',
    '1c' : 'SHR',
    '1d' : 'SAR',
    '20' : 'SHA3',
    '30' : 'ADDRESS',
    '31' : 'BALANCE',
    '32' : 'ORIGIN',
    '33' : 'CALLER',
    '34' : 'CALLVALUE',
    '35' : 'CALLDATALOAD',
    '36' : 'CALLDATASIZE',
    '37' : 'CALLDATACOPY',
    '38' : 'CODESIZE',
    '39' : 'CODECOPY',
    '3a' : 'GASPRICE',
    '3b' : 'EXTCODESIZE',
    '3c' : 'EXTCODECOPY',
    '3d' : 'RETURNDATASIZE',
    '3e' : 'RETURNDATACOPY',
    '3f' : 'EXTCODEHASH',
    '40' : 'BLOCKHASH',
    '41' : 'COINBASE',
    '42' : 'TIMESTAMP',
    '43' : 'NUMBER',
    '44' : 'DIFFICULTY',
    '45' : 'GASLIMIT',
    '46' : 'CHAINID',
    '47' : 'SELFBALANCE',
    '50' : 'POP',
    '51' : 'MLOAD',
    '52' : 'MSTORE',
    '53' : 'MSTORE8',
    '54' : 'SLOAD',
    '55' : 'SSTORE',
    '56' : 'JUMP',
    '57' : 'JUMPI',
    '58' : 'PC',
    '59' : 'MSIZE',
    '5a' : 'GAS',
    '5b' : 'JUMPDEST',
    '60' : 'PUSH1',
    '61' : 'PUSH2',
    '62' : 'PUSH3',
    '63' : 'PUSH4',
    '64' : 'PUSH5',
    '65' : 'PUSH6',
    '66' : 'PUSH7',
    '67' : 'PUSH8',
    '68' : 'PUSH9',
    '69' : 'PUSH10',
    '6a' : 'PUSH11',
    '6b' : 'PUSH12',
    '6c' : 'PUSH13',
    '6d' : 'PUSH14',
    '6e' : 'PUSH15',
    '6f' : 'PUSH16',
    '70' : 'PUSH17',
    '71' : 'PUSH18',
    '72' : 'PUSH19',
    '73' : 'PUSH20',
    '74' : 'PUSH21',
    '75' : 'PUSH22',
    '76' : 'PUSH23',
    '77' : 'PUSH24',
    '78' : 'PUSH25',
    '79' : 'PUSH26',
    '7a' : 'PUSH27',
    '7b' : 'PUSH28',
    '7c' : 'PUSH29',
    '7d' : 'PUSH30',
    '7e' : 'PUSH31',
    '7f' : 'PUSH32',
    '80' : 'DUP1',
    '81' : 'DUP2',
    '82' : 'DUP3',
    '83' : 'DUP4',
    '84' : 'DUP5',
    '85' : 'DUP6',
    '86' : 'DUP7',
    '87' : 'DUP8',
    '88' : 'DUP9',
    '89' : 'DUP10',
    '8a' : 'DUP11',
    '8b' : 'DUP12',
    '8c' : 'DUP13',
    '8d' : 'DUP14',
    '8e' : 'DUP15',
    '8f' : 'DUP16',
    '90' : 'SWAP1',
    '91' : 'SWAP2',
    '92' : 'SWAP3',
    '93' : 'SWAP4',
    '94' : 'SWAP5',
    '95' : 'SWAP6',
    '96' : 'SWAP7',
    '97' : 'SWAP8',
    '98' : 'SWAP9',
    '99' : 'SWAP10',
    '9a' : 'SWAP11',
    '9b' : 'SWAP12',
    '9c' : 'SWAP13',
    '9d' : 'SWAP14',
    '9e' : 'SWAP15',
    '9f' : 'SWAP16',
    'a0' : 'LOG0',
    'a1' : 'LOG1',
    'a2' : 'LOG2',
    'a3' : 'LOG3',
    'a4' : 'LOG4',
    'f0' : 'CREATE',
    'f1' : 'CALL',
    'f2' : 'CALLCODE',
    'f3' : 'RETURN',
    'f4' : 'DELEGATECALL',
    'f5' : 'CREATE2',
    'fa' : 'STATICCALL',
    'fd' : 'REVERT',
    'fe' : 'INVALID',
    'ff' : 'SELFDESTRUCT',
#   'ff' : 'SUICIDE',
}

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
