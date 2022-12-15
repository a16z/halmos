# SPDX-License-Identifier: AGPL-3.0

from typing import List, Dict, Tuple, Any
from collections import defaultdict

def groupby_gas(cnts: Dict[str,int]) -> Dict[str,int]:
    new_cnts = defaultdict(int)

    for (op, cnt) in cnts.items():
        if (
               op == 'STOP'
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
