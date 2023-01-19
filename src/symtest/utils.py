# SPDX-License-Identifier: AGPL-3.0

from typing import Dict
from collections import defaultdict

def color_good(text: str) -> str:
    return '\033[32m' + text + '\033[0m'

def color_warn(text: str) -> str:
    return '\033[31m' + text + '\033[0m'

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

class hevm_cheat_code:
    # https://github.com/dapphub/ds-test/blob/cd98eff28324bfac652e63a239a60632a761790b/src/test.sol

    # address constant HEVM_ADDRESS =
    #     address(bytes20(uint160(uint256(keccak256('hevm cheat code')))));
    address: int = 0x7109709ECfa91a80626fF3989D68f67F5b1DD12D

    # abi.encodePacked(
    #     bytes4(keccak256("store(address,bytes32,bytes32)")),
    #     abi.encode(HEVM_ADDRESS, bytes32("failed"), bytes32(uint256(0x01)))
    # )
    fail_payload: int = int(
        '70ca10bb' +
        '0000000000000000000000007109709ecfa91a80626ff3989d68f67f5b1dd12d' +
        '6661696c65640000000000000000000000000000000000000000000000000000' +
        '0000000000000000000000000000000000000000000000000000000000000001', 16
    )

    # bytes4(keccak256("assume(bool)"))
    assume_sig: int = 0x4C63E562
