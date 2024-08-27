import pytest
from z3 import (
    UGT,
    ULT,
    Array,
    BitVec,
    BitVecSort,
    BitVecVal,
    Concat,
    Extract,
    If,
    LShR,
    Select,
    SignExt,
    ZeroExt,
    simplify,
)

from halmos.__main__ import mk_block
from halmos.bytevec import ByteVec
from halmos.exceptions import OutOfGasError, StackUnderflowError
from halmos.sevm import (
    SEVM,
    CallContext,
    Contract,
    Exec,
    Message,
    Path,
    con,
    f_div,
    f_exp,
    f_mod,
    f_mul,
    f_sdiv,
    f_smod,
    int_of,
    uint160,
    uint256,
)
from halmos.utils import EVM

caller = BitVec("msg_sender", 160)
origin = BitVec("tx_origin", 160)
this = BitVec("this_address", 160)

balance = Array("balance_0", BitVecSort(160), BitVecSort(256))
callvalue = BitVec("msg_value", 256)


@pytest.fixture
def storage():
    return {}


def mk_ex(hexcode, sevm, solver, storage, caller, this):
    bytecode = Contract(hexcode)

    message = Message(
        target=this,
        caller=caller,
        origin=origin,
        value=callvalue,
        data=ByteVec(),
        call_scheme=EVM.CALL,
    )

    return sevm.mk_exec(
        code={this: bytecode},
        storage={this: storage},
        balance=balance,
        block=mk_block(),
        context=CallContext(message),
        pgm=bytecode,
        path=Path(solver),
    )


x = BitVec("x", 256)
y = BitVec("y", 256)
z = BitVec("z", 256)


def o(opcode):
    return BitVecVal(opcode, 8)


@pytest.mark.parametrize(
    "hexcode, stack, pc, opcode",
    [
        (BitVecVal(0x600100, 24), "[1]", 2, EVM.STOP),
        # symbolic opcodes are not supported
        # (BitVec('x', 256), '[]', 0, 'Extract(255, 248, x)'),
        # (Concat(BitVecVal(int('6001', 16), 16), BitVec('x', 8), BitVecVal(0, 8)), '[1]', 2, 'x'),
        (
            Concat(BitVecVal(0x6101, 16), BitVec("x", 8), BitVecVal(0, 8)),
            "[Concat(1, x)]",
            3,
            EVM.STOP,
        ),
        (BitVecVal(0x58585B5860015800, 64), "[0, 1, 3, 1, 6]", 7, EVM.STOP),
    ],
)
def test_run(hexcode, stack, pc, opcode: int, sevm, solver, storage):
    ex = mk_ex(hexcode, sevm, solver, storage, caller, this)
    exs = list(sevm.run(ex))
    assert len(exs) == 1
    ex: Exec = exs[0]
    assert str(ex.st.stack) == stack
    assert ex.pc == pc
    assert ex.current_opcode() == int_of(opcode)


def byte_of(i, x):
    # fmt: off
    return ZeroExt(248,
        If(i == con( 0), Extract(255, 248, x),
        If(i == con( 1), Extract(247, 240, x),
        If(i == con( 2), Extract(239, 232, x),
        If(i == con( 3), Extract(231, 224, x),
        If(i == con( 4), Extract(223, 216, x),
        If(i == con( 5), Extract(215, 208, x),
        If(i == con( 6), Extract(207, 200, x),
        If(i == con( 7), Extract(199, 192, x),
        If(i == con( 8), Extract(191, 184, x),
        If(i == con( 9), Extract(183, 176, x),
        If(i == con(10), Extract(175, 168, x),
        If(i == con(11), Extract(167, 160, x),
        If(i == con(12), Extract(159, 152, x),
        If(i == con(13), Extract(151, 144, x),
        If(i == con(14), Extract(143, 136, x),
        If(i == con(15), Extract(135, 128, x),
        If(i == con(16), Extract(127, 120, x),
        If(i == con(17), Extract(119, 112, x),
        If(i == con(18), Extract(111, 104, x),
        If(i == con(19), Extract(103,  96, x),
        If(i == con(20), Extract( 95,  88, x),
        If(i == con(21), Extract( 87,  80, x),
        If(i == con(22), Extract( 79,  72, x),
        If(i == con(23), Extract( 71,  64, x),
        If(i == con(24), Extract( 63,  56, x),
        If(i == con(25), Extract( 55,  48, x),
        If(i == con(26), Extract( 47,  40, x),
        If(i == con(27), Extract( 39,  32, x),
        If(i == con(28), Extract( 31,  24, x),
        If(i == con(29), Extract( 23,  16, x),
        If(i == con(30), Extract( 15,   8, x),
        If(i == con(31), Extract(  7,   0, x),
        BitVecVal(0, 8)))))))))))))))))))))))))))))))))
    )


@pytest.mark.parametrize(
    "hexcode, params, output",
    [
        (o(EVM.PUSH0), [], con(0)),
        (o(EVM.ADD), [x, y], x + y),
        (o(EVM.MUL), [x, y], f_mul[x.size()](x, y)),
        (o(EVM.SUB), [x, y], x - y),
        (o(EVM.DIV), [x, y], f_div(x, y)),
        (o(EVM.DIV), [con(5), con(3)], con(1)),
        (o(EVM.DIV), [x, con(0)], con(0)),
        (o(EVM.DIV), [x, con(1)], x),
        (o(EVM.DIV), [x, con(2**3)], LShR(x, 3)),
        (o(EVM.SDIV), [x, y], f_sdiv(x, y)),
        (o(EVM.SDIV), [con(5), con(3)], con(1)),
        (o(EVM.SDIV), [con(-5), con(3)], con(-1)),
        (o(EVM.SDIV), [con(5), con(-3)], con(-1)),
        (o(EVM.SDIV), [con(-5), con(-3)], con(1)),
        (o(EVM.SDIV), [con(-(2**255)), con(-1)], con(-(2**255))),  # overflow
        (o(EVM.SDIV), [con(-(2**255)), con(-1)], con(2**255)),  # overflow
        (o(EVM.MOD), [x, y], f_mod[x.size()](x, y)),
        (o(EVM.MOD), [con(5), con(3)], con(2)),
        (o(EVM.MOD), [x, con(0)], con(0)),
        (o(EVM.MOD), [x, con(1)], con(0)),
        (o(EVM.MOD), [x, con(2**3)], ZeroExt(253, Extract(2, 0, x))),
        (o(EVM.SMOD), [x, y], f_smod(x, y)),  # sdiv(x,y) * y + smod(x,y) == x
        (o(EVM.SMOD), [con(5), con(3)], con(2)),
        (o(EVM.SMOD), [con(-5), con(3)], con(-2)),
        (o(EVM.SMOD), [con(5), con(-3)], con(2)),
        (o(EVM.SMOD), [con(-5), con(-3)], con(-2)),
        (o(EVM.ADDMOD), [con(4), con(1), con(3)], con(2)),
        (o(EVM.ADDMOD), [x, y, con(0)], con(0)),
        (o(EVM.ADDMOD), [x, y, con(1)], con(0)),
        (
            o(EVM.ADDMOD),
            [x, y, con(2**3)],
            ZeroExt(253, Extract(2, 0, ZeroExt(8, x) + ZeroExt(8, y))),
        ),
        (
            o(EVM.ADDMOD),
            [x, y, z],
            Extract(255, 0, f_mod[264](ZeroExt(8, x) + ZeroExt(8, y), ZeroExt(8, z))),
        ),
        (o(EVM.ADDMOD), [con(10), con(10), con(8)], con(4)),
        (
            o(EVM.ADDMOD),
            [
                con(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
                con(2),
                con(2),
            ],
            con(1),
        ),
        (o(EVM.MULMOD), [con(5), con(1), con(3)], con(2)),
        (o(EVM.MULMOD), [x, y, con(0)], con(0)),
        (o(EVM.MULMOD), [x, y, con(1)], con(0)),
        (
            o(EVM.MULMOD),
            [x, y, con(2**3)],
            ZeroExt(253, Extract(2, 0, f_mul[512](ZeroExt(256, x), ZeroExt(256, y)))),
        ),
        (
            o(EVM.MULMOD),
            [x, y, z],
            Extract(
                255,
                0,
                f_mod[512](
                    f_mul[512](ZeroExt(256, x), ZeroExt(256, y)), ZeroExt(256, z)
                ),
            ),
        ),
        (o(EVM.MULMOD), [con(10), con(10), con(8)], con(4)),
        (
            o(EVM.MULMOD),
            [
                con(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
                con(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
                con(12),
            ],
            con(9),
        ),
        (o(EVM.EXP), [x, y], f_exp(x, y)),
        (o(EVM.EXP), [x, con(0)], con(1)),
        (o(EVM.EXP), [x, con(1)], x),
        (o(EVM.EXP), [x, con(2)], f_mul[x.size()](x, x)),
        (o(EVM.SIGNEXTEND), [con(0), y], SignExt(248, Extract(7, 0, y))),
        (o(EVM.SIGNEXTEND), [con(1), y], SignExt(240, Extract(15, 0, y))),
        (o(EVM.SIGNEXTEND), [con(30), y], SignExt(8, Extract(247, 0, y))),
        (o(EVM.SIGNEXTEND), [con(31), y], y),
        (o(EVM.SIGNEXTEND), [con(32), y], y),
        (o(EVM.SIGNEXTEND), [con(33), y], y),
        (o(EVM.SIGNEXTEND), [con(2**256 - 1), y], y),
        (o(EVM.LT), [x, y], ULT(x, y)),
        (o(EVM.GT), [x, y], UGT(x, y)),
        (o(EVM.SLT), [x, y], x < y),
        (o(EVM.SGT), [x, y], x > y),
        (o(EVM.EQ), [x, y], x == y),
        (o(EVM.ISZERO), [x], x == con(0)),
        (o(EVM.AND), [x, y], x & y),
        (o(EVM.OR), [x, y], x | y),
        (o(EVM.XOR), [x, y], x ^ y),
        (o(EVM.NOT), [x], ~x),
        (o(EVM.BYTE), [con(0), y], ZeroExt(248, Extract(255, 248, y))),
        (o(EVM.BYTE), [con(1), y], ZeroExt(248, Extract(247, 240, y))),
        (o(EVM.BYTE), [con(31), y], ZeroExt(248, Extract(7, 0, y))),
        (o(EVM.BYTE), [con(32), y], con(0)),
        (o(EVM.BYTE), [con(33), y], con(0)),
        (o(EVM.BYTE), [con(2**256 - 1), y], con(0)),
        (o(EVM.BYTE), [x, y], byte_of(x, y)),
        (o(EVM.SHL), [x, y], y << x),
        (o(EVM.SHL), [con(0), y], y),
        (o(EVM.SHL), [con(255), y], y << con(255)),
        (o(EVM.SHL), [con(256), y], con(0)),
        (o(EVM.SHL), [con(2**256 - 1), y], con(0)),
        (o(EVM.SHR), [x, y], LShR(y, x)),
        (o(EVM.SHR), [con(0), y], y),
        (o(EVM.SHR), [con(255), y], LShR(y, con(255))),
        (o(EVM.SHR), [con(256), y], con(0)),
        (o(EVM.SHR), [con(2**256 - 1), y], con(0)),
        (o(EVM.SAR), [x, y], y >> x),
        (o(EVM.SAR), [con(0), y], y),
        (o(EVM.SAR), [con(255), y], y >> con(255)),
        (
            o(EVM.SAR),
            [con(256), y],
            y >> con(256),
        ),  # not necessarily 0; TODO: prove it is equal to y >> 255
        (
            o(EVM.SAR),
            [con(2**256 - 1), y],
            y >> con(2**256 - 1),
        ),  # not necessarily 0; TODO: prove it is equal to y >> 255
        # TODO: SHA3
        (o(EVM.ADDRESS), [], uint256(this)),
        (o(EVM.BALANCE), [x], Select(balance, uint160(x))),
        (o(EVM.ORIGIN), [], uint256(origin)),
        (o(EVM.CALLER), [], uint256(caller)),
        (o(EVM.CALLVALUE), [], callvalue),
        # TODO: CALLDATA*, CODE*, EXTCODE*, RETURNDATA*, CREATE*
        (o(EVM.SELFBALANCE), [], Select(balance, this)),
    ],
)
def test_opcode_simple(hexcode, params, output, sevm: SEVM, solver, storage):
    ex = mk_ex(Concat(hexcode, o(EVM.STOP)), sevm, solver, storage, caller, this)

    # reversed because in the tests the stack is written with the top on the left
    # but in the internal state, the top of the stack is the last element of the list
    ex.st.stack.extend(reversed(params))
    exs: list[Exec] = list(sevm.run(ex))

    [output_ex] = exs
    assert output_ex.st.stack.pop() == simplify(output)


@pytest.mark.parametrize(
    "hexcode, stack_in, stack_out",
    [
        (o(EVM.SWAP1), [x, y, z], [y, x, z]),
        (o(EVM.SWAP2), [x, y, z], [z, y, x]),
        (o(EVM.SWAP3), [x, 1, 2, y, 3], [y, 1, 2, x, 3]),
        (o(EVM.SWAP4), [x, 1, 2, 3, y, 4], [y, 1, 2, 3, x, 4]),
        (o(EVM.SWAP5), [x, 1, 2, 3, 4, y, 5], [y, 1, 2, 3, 4, x, 5]),
        (o(EVM.SWAP6), [x, 1, 2, 3, 4, 5, y, 6], [y, 1, 2, 3, 4, 5, x, 6]),
        (o(EVM.SWAP7), [x, 1, 2, 3, 4, 5, 6, y, 7], [y, 1, 2, 3, 4, 5, 6, x, 7]),
        (o(EVM.SWAP8), [x, 1, 2, 3, 4, 5, 6, 7, y, 8], [y, 1, 2, 3, 4, 5, 6, 7, x, 8]),
        (o(EVM.SWAP9), [x] + [0] * 8 + [y, 9], [y] + [0] * 8 + [x, 9]),
        (o(EVM.SWAP10), [x] + [0] * 9 + [y, 10], [y] + [0] * 9 + [x, 10]),
        (o(EVM.SWAP11), [x] + [0] * 10 + [y, 11], [y] + [0] * 10 + [x, 11]),
        (o(EVM.SWAP12), [x] + [0] * 11 + [y, 12], [y] + [0] * 11 + [x, 12]),
        (o(EVM.SWAP13), [x] + [0] * 12 + [y, 13], [y] + [0] * 12 + [x, 13]),
        (o(EVM.SWAP14), [x] + [0] * 13 + [y, 14], [y] + [0] * 13 + [x, 14]),
        (o(EVM.SWAP15), [x] + [0] * 14 + [y, 15], [y] + [0] * 14 + [x, 15]),
        (o(EVM.SWAP16), [x] + [0] * 15 + [y, 16], [y] + [0] * 15 + [x, 16]),
    ],
)
def test_opcode_stack(hexcode, stack_in, stack_out, sevm: SEVM, solver, storage):
    ex = mk_ex(Concat(hexcode, o(EVM.STOP)), sevm, solver, storage, caller, this)

    # reversed because in the tests the stack is written with the top on the left
    # but in the internal state, the top of the stack is the last element of the list
    ex.st.stack.extend(reversed(stack_in))
    exs: list[Exec] = list(sevm.run(ex))

    [output_ex] = exs
    assert output_ex.st.stack == list(reversed(stack_out))


def test_stack_underflow_pop(sevm: SEVM, solver, storage):
    # check that we get an exception when popping from an empty stack
    ex = mk_ex(o(EVM.POP), sevm, solver, storage, caller, this)

    exs: list[Exec] = list(sevm.run(ex))

    [output_ex] = exs
    assert isinstance(output_ex.context.output.error, StackUnderflowError)


def test_large_memory_offset(sevm: SEVM, solver, storage):
    for op in [o(EVM.MLOAD), o(EVM.MSTORE), o(EVM.MSTORE8)]:
        ex = mk_ex(op, sevm, solver, storage, caller, this)
        ex.st.stack.append(con(42))  # value, ignored by MLOAD
        ex.st.stack.append(con(2**64))  # offset too big to fit in memory

    exs: list[Exec] = list(sevm.run(ex))

    [output_ex] = exs
    assert isinstance(output_ex.context.output.error, OutOfGasError)
