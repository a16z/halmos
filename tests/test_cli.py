import json

import pytest
from z3 import (
    BitVec,
    BitVecVal,
    Concat,
)

from halmos.calldata import str_abi
from halmos.sevm import Contract, Instruction, con
from halmos.utils import EVM, hexify


@pytest.fixture
def setup_abi():
    return json.loads(
        """
[
    {
      "inputs": [],
      "name": "setUp",
      "outputs": [],
      "stateMutability": "nonpayable",
      "type": "function"
    }
]
    """
    )


@pytest.fixture
def setup_name():
    return "setUp"


@pytest.fixture
def setup_sig():
    return "setUp()"


@pytest.fixture
def setup_selector():
    return "0a9254e4"


def test_decode_concrete_bytecode():
    hexcode = "34381856FDFDFDFDFDFD5B00"
    contract = Contract.from_hexcode(hexcode)

    # length of the bytecode
    assert len(contract) == 12

    # random data access
    assert contract[0] == EVM.CALLVALUE
    assert contract[1] == EVM.CODESIZE
    assert contract[10] == EVM.JUMPDEST
    assert contract[11] == EVM.STOP

    # jump destination scanning
    assert contract.valid_jump_destinations() == set([10])


def test_decode_mixed_bytecode():
    # mix of bytes and bitvectors as a single bitvector expression
    contract = Contract(
        Concat(
            BitVecVal(EVM.PUSH20, 8),
            BitVec("x", 160),
            BitVecVal(0x5F526014600CF3, 7 * 8),
        )
    )

    # length of the bytecode
    assert len(contract) == 28

    # random data access
    assert contract[0] == EVM.PUSH20
    assert contract[27] == EVM.RETURN
    assert contract[28] == EVM.STOP  # past the end
    assert contract.valid_jump_destinations() == set()

    # force decoding
    pc = 0
    while pc < len(contract):
        contract.decode_instruction(pc)
        pc = contract.next_pc(pc)

    pcs, insns = zip(
        *((pc, insn) for (pc, insn) in contract._insn.items()), strict=False
    )
    opcodes = tuple(insn.opcode for insn in insns)

    assert opcodes == (
        EVM.PUSH20,
        EVM.PUSH0,
        EVM.MSTORE,
        EVM.PUSH1,
        EVM.PUSH1,
        EVM.RETURN,
    )

    disassembly = " ".join([str(insn) for insn in insns])
    assert disassembly == "PUSH20 x() PUSH0 MSTORE PUSH1 0x14 PUSH1 0x0c RETURN"

    # jump destination scanning
    assert contract.valid_jump_destinations() == set()


def test_instruction():
    assert str(Instruction(con(0))) == "STOP"
    assert str(Instruction(con(1))) == "ADD"

    push32_1_str = "PUSH32 " + hexify(con(1))
    assert str(Instruction(con(EVM.PUSH32), operand=con(1))) == push32_1_str
    assert str(Instruction(con(EVM.BASEFEE))) == "BASEFEE"

    # symbolic opcode is not supported
    # assert str(Instruction(BitVec('x', 8))) == 'x'
    # assert str(Instruction(BitVec('x', 8), operand=BitVec('y', 8), pc=BitVec('z', 16))) == 'x y'

    assert str(Instruction(EVM.STOP)) == "STOP"
    assert str(Instruction(EVM.ADD)) == "ADD"
    assert (
        str(Instruction(EVM.PUSH32, operand=bytes.fromhex("00" * 31 + "01")))
        == push32_1_str
    )


def test_decode_hex():
    code = Contract.from_hexcode("600100")
    assert str(code.decode_instruction(0)) == f"PUSH1 {hexify(1)}"

    code = Contract.from_hexcode("01")
    assert str(code.decode_instruction(0)) == "ADD"

    with pytest.raises(ValueError, match="1"):
        Contract.from_hexcode("1")


def test_decode():
    code = Contract(Concat(BitVecVal(EVM.PUSH32, 8), BitVec("x", 256)))
    assert len(code) == 33
    assert str(code.decode_instruction(0)) == "PUSH32 x()"
    assert str(code.decode_instruction(33)) == "STOP"

    code = Contract(BitVec("x", 256))
    assert len(code) == 32
    assert str(code[31]) == "Extract(7, 0, x)"

    code = Contract(Concat(BitVecVal(EVM.PUSH3, 8), BitVec("x", 16)))
    assert (
        str(code.decode_instruction(0)) == "PUSH3 Concat(x(), 0x00)"
    )  # 'PUSH3 ERROR x (1 bytes missed)'


@pytest.mark.parametrize(
    "sig,abi",
    [
        (
            "fooInt(uint256)",
            """
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
    """,
        ),
        (
            "fooInt8(uint8)",
            """
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
    """,
        ),
        (
            "fooIntAddress(uint256,address)",
            """
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
    """,
        ),
        (
            "fooIntInt(uint256,uint256)",
            """
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
    """,
        ),
        (
            "fooStruct(((uint256,uint256),uint256),uint256)",
            """
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
    """,
        ),
        (
            "fooStructArr(uint256,(uint256,uint256)[])",
            """
    {
        "type": "function",
        "name": "fooStructArr",
        "inputs": [
            {
                "name": "param1",
                "type": "uint256",
                "internalType": "uint256"
            },
            {
                "name": "param2",
                "type": "tuple[]",
                "internalType": "struct S[]",
                "components": [
                    {
                        "name": "x",
                        "type": "uint256",
                        "internalType": "uint256"
                    },
                    {
                        "name": "y",
                        "type": "uint256",
                        "internalType": "uint256"
                    }
                ]
            }
        ],
        "outputs": [],
        "stateMutability": "nonpayable"
    }
    """,
        ),
        (
            "fooDynArr(uint256[])",
            """
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
    """,
        ),
        (
            "fooFixArr(uint256[3])",
            """
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
    """,
        ),
        (
            "fooBytes(bytes)",
            """
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
    """,
        ),
    ],
    ids=(
        "fooInt(uint256)",
        "fooInt8(uint8)",
        "fooIntAddress(uint256,address)",
        "fooIntInt(uint256,uint256)",
        "fooStruct(((uint256,uint256),uint256),uint256)",
        "fooStructArr(uint256,(uint256,uint256)[])",
        "fooDynArr(uint256[])",
        "fooFixArr(uint256[3])",
        "fooBytes(bytes)",
    ),
)
def test_str_abi(sig, abi):
    assert sig == str_abi(json.loads(abi))
