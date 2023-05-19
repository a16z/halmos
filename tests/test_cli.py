import pytest
import json

from z3 import *

from halmos.utils import EVM

from halmos.byte2op import decode, Opcode

from halmos.sevm import con, Contract

from halmos.__main__ import str_abi, run_bytecode
import halmos.__main__

from test_fixtures import args, options

@pytest.fixture
def setup_abi():
    return json.loads("""
[
    {
      "inputs": [],
      "name": "setUp",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
]
    """)

@pytest.fixture
def setup_name():
    return 'setUp'

@pytest.fixture
def setup_sig():
    return 'setUp()'

@pytest.fixture
def setup_selector():
    return int('0a9254e4', 16)


def test_decode_concrete_bytecode():
    hexcode = '34381856FDFDFDFDFDFD5B00'
    contract = Contract.from_hexcode(hexcode)

    # length of the bytecode
    assert len(contract) == 12

    # random data access
    assert contract[0] == EVM.CALLVALUE
    assert contract[1] == EVM.CODESIZE
    assert contract[-2] == EVM.JUMPDEST
    assert contract[-1] == EVM.STOP

    # iteration
    opcodes = [opcode for (pc, opcode) in contract]
    assert bytes(opcodes).hex() == hexcode.lower()

    # jump destination scanning
    assert contract.valid_jump_destinations() == set([10])


def test_decode_mixed_bytecode():
    # 73x5f526014600cf3 is bytecode that returns a symbolic address x:
    # push20 x push0 mstore
    # push1 20 push1 12 return

    # mix of bytes and bitvectors
    mixed_concrete_symbolic = Contract([b'\x73', BitVec('x', 160), b'\x5f\x52\x60\x14\x60\x0c\xf3'])

    # same thing, but with as a single bitvector expression
    concat_concrete_symbolic = Contract.from_bitvec(
        Concat(
            BitVecVal(EVM.PUSH20, 8),
            BitVec('x', 160),
            BitVecVal(0x5f526014600cf3, 7 * 8)
        )
    )

    for contract in (mixed_concrete_symbolic, concat_concrete_symbolic):
        # length of the bytecode
        assert len(contract) == 28

        # random data access
        assert contract[0] == EVM.PUSH20
        assert contract[-1] == EVM.RETURN
        assert contract[28] == EVM.STOP # past the end

        # iteration
        opcodes = [opcode for (pc, opcode) in contract]
        assert opcodes == [EVM.PUSH20, EVM.PUSH0, EVM.MSTORE, EVM.PUSH1, EVM.PUSH1, EVM.RETURN]

        # jump destination scanning
        assert contract.valid_jump_destinations() == set()


def test_run_bytecode(args, options):
    hexcode = '34381856FDFDFDFDFDFD5B00'
    options['sym_jump'] = True
    exs = run_bytecode(hexcode, args, options)
    assert len(exs) == 1
    ex = exs[0]
    assert str(ex.code[ex.this][ex.pc]) == EVM.STOP

def test_setup(setup_abi, setup_name, setup_sig, setup_selector, args, options):
    hexcode = '600100'
    abi = setup_abi
    arrlen = {}
    setup_ex = halmos.__main__.setup(hexcode, abi, setup_name, setup_sig, setup_selector, arrlen, args, options)
    assert str(setup_ex.st.stack) == '[1]'

def test_opcode():
    assert str(Opcode(0, [con(0)])) == 'STOP'
    assert str(Opcode(0, [con(1)])) == 'ADD'
    assert str(Opcode(0, [con(EVM.PUSH32), con(1)])) == 'PUSH32 1'
    assert str(Opcode(0, [con(EVM.BASEFEE)])) == 'BASEFEE'
    assert str(Opcode(0, [BitVec('x',8)])) == 'x'
    assert str(Opcode(0, [BitVec('x',8), BitVec('y',8)])) == 'x y'
    assert str(Opcode(0, [BitVec('x',8), BitVec('y',8), BitVec('z',8)])) == 'x y'

def test_decode_hex():
    (pgm, code) = decode_hex('600100')
    assert str(pgm[0]) == 'PUSH1 1'
    assert str(code) == '[96, 1, 0]'

    (pgm, code) = decode_hex('01')
    assert str(pgm[0]) == 'ADD'
    assert str(code) == '[1]'

    with pytest.raises(ValueError, match='1'):
        decode_hex('1')

def test_decode():
    (ops, code) = decode(Concat(BitVecVal(EVM.PUSH32, 8), BitVec('x', 256)))
    assert ','.join(map(str,ops)) == 'PUSH32 x'

    (ops, code) = decode(BitVec('x', 256))
    assert len(ops) == 32
    assert str(ops[-1]) == 'Extract(7, 0, x)'

    (ops, code) = decode(Concat(BitVecVal(EVM.PUSH3, 8), BitVec('x', 16)))
    assert len(ops) == 1
    assert str(ops[0]) == 'PUSH3 ERROR x (1 bytes missed)'

@pytest.mark.parametrize('sig,abi', [
    ('fooInt(uint256)', """
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "x",
          "type": "uint256"
        }
      ],
      "name": "fooInt",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
    """),
    ('fooInt8(uint8)', """
    {
      "inputs": [
        {
          "internalType": "uint8",
          "name": "x",
          "type": "uint8"
        }
      ],
      "name": "fooInt8",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
    """),
    ('fooIntAddress(uint256,address)', """
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "x",
          "type": "uint256"
        },
        {
          "internalType": "address",
          "name": "y",
          "type": "address"
        }
      ],
      "name": "fooIntAddress",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
    """),
    ('fooIntInt(uint256,uint256)', """
    {
      "inputs": [
        {
          "internalType": "uint256",
          "name": "x",
          "type": "uint256"
        },
        {
          "internalType": "uint256",
          "name": "y",
          "type": "uint256"
        }
      ],
      "name": "fooIntInt",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
    """),
    # TODO: fix crytic-compile bug
    # 'fooStruct(((uint256,uint256),uint256),uint256)'
    ('fooStruct(tuple,uint256)', """
    {
      "inputs": [
        {
          "components": [
            {
              "components": [
                {
                  "internalType": "uint256",
                  "name": "x",
                  "type": "uint256"
                },
                {
                  "internalType": "uint256",
                  "name": "y",
                  "type": "uint256"
                }
              ],
              "internalType": "struct Abi.S",
              "name": "s",
              "type": "tuple"
            },
            {
              "internalType": "uint256",
              "name": "z",
              "type": "uint256"
            }
          ],
          "internalType": "struct Abi.R",
          "name": "x",
          "type": "tuple"
        },
        {
          "internalType": "uint256",
          "name": "y",
          "type": "uint256"
        }
      ],
      "name": "fooStruct",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
    """),
    ('fooDynArr(uint256[])', """
    {
      "inputs": [
        {
          "internalType": "uint256[]",
          "name": "x",
          "type": "uint256[]"
        }
      ],
      "name": "fooDynArr",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
    """),
    ('fooFixArr(uint256[3])', """
    {
      "inputs": [
        {
          "internalType": "uint256[3]",
          "name": "x",
          "type": "uint256[3]"
        }
      ],
      "name": "fooFixArr",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
    """),
    ('fooBytes(bytes)', """
    {
      "inputs": [
        {
          "internalType": "bytes",
          "name": "x",
          "type": "bytes"
        }
      ],
      "name": "fooBytes",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
    """),
])
def test_str_abi(sig, abi):
    assert sig == str_abi(json.loads(abi))
