import pytest
import json

from z3 import *

from halmos.utils import EVM

from halmos.sevm import con, Contract, Instruction

from halmos.__main__ import str_abi, run_bytecode, FunctionInfo

from test_fixtures import args, options


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
    assert contract[-2] == EVM.JUMPDEST
    assert contract[-1] == EVM.STOP

    # iteration
    opcodes = [insn.opcode for insn in contract]
    assert bytes(opcodes).hex() == hexcode.lower()

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
    assert contract[-1] == EVM.RETURN
    assert contract[28] == EVM.STOP  # past the end

    # iteration
    opcodes = [insn.opcode for insn in contract]
    assert opcodes == [
        EVM.PUSH20,
        EVM.PUSH0,
        EVM.MSTORE,
        EVM.PUSH1,
        EVM.PUSH1,
        EVM.RETURN,
    ]

    disassembly = "\n".join([str(insn) for insn in contract])
    assert disassembly == (
        """PUSH20 x
PUSH0
MSTORE
PUSH1 20
PUSH1 12
RETURN"""
    )

    # jump destination scanning
    assert contract.valid_jump_destinations() == set()


def test_run_bytecode(args):
    # sets the flag in the global args for the main module
    args.symbolic_jump = True

    hexcode = "34381856FDFDFDFDFDFD5B00"
    exs = run_bytecode(hexcode, args)
    assert len(exs) == 1
    assert exs[0].current_opcode() == EVM.STOP


def test_instruction():
    assert str(Instruction(con(0))) == "STOP"
    assert str(Instruction(con(1))) == "ADD"
    assert str(Instruction(con(EVM.PUSH32), operand=con(1))) == "PUSH32 1"
    assert str(Instruction(con(EVM.BASEFEE))) == "BASEFEE"

    # symbolic opcode is not supported
    # assert str(Instruction(BitVec('x', 8))) == 'x'
    # assert str(Instruction(BitVec('x', 8), operand=BitVec('y', 8), pc=BitVec('z', 16))) == 'x y'

    assert str(Instruction(EVM.STOP)) == "STOP"
    assert str(Instruction(EVM.ADD)) == "ADD"
    assert (
        str(Instruction(EVM.PUSH32, operand=bytes.fromhex("00" * 31 + "01")))
        == "PUSH32 1"
    )


def test_decode_hex():
    code = Contract.from_hexcode("600100")
    assert str(code.decode_instruction(0)) == "PUSH1 1"
    assert [insn.opcode for insn in code] == [0x60, 0x00]

    code = Contract.from_hexcode("01")
    assert str(code.decode_instruction(0)) == "ADD"
    assert [insn.opcode for insn in code] == [1]

    with pytest.raises(ValueError, match="1"):
        Contract.from_hexcode("1")


def test_decode():
    code = Contract(Concat(BitVecVal(EVM.PUSH32, 8), BitVec("x", 256)))
    assert len(code) == 33
    assert str(code.decode_instruction(0)) == "PUSH32 x"
    assert str(code.decode_instruction(33)) == "STOP"

    code = Contract(BitVec("x", 256))
    assert len(code) == 32
    assert str(code[-1]) == "Extract(7, 0, x)"

    code = Contract(Concat(BitVecVal(EVM.PUSH3, 8), BitVec("x", 16)))
    ops = [insn for insn in code]
    assert len(ops) == 1
    assert str(ops[0]) == "PUSH3 Concat(x, 0)"  # 'PUSH3 ERROR x (1 bytes missed)'


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
        "fooDynArr(uint256[])",
        "fooFixArr(uint256[3])",
        "fooBytes(bytes)",
    ),
)
def test_str_abi(sig, abi):
    assert sig == str_abi(json.loads(abi))
