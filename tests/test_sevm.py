import pytest
from z3 import (
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
)

from halmos.__main__ import mk_block
from halmos.bitvec import HalmosBitVec as BV
from halmos.bytevec import ByteVec
from halmos.exceptions import (
    InvalidJumpDestError,
    InvalidOpcode,
    OutOfGasError,
    StackUnderflowError,
)
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

BV_1234000000dcba = BV(
    0x11223344000000000000000000000000000000000000000000000000DDCCBBAA
)


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
        transient_storage={this: storage},
        balance=balance,
        block=mk_block(),
        context=CallContext(message),
        pgm=bytecode,
        path=Path(solver),
    )


x = BV("x")
y = BV("y")
z = BV("z")


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
    "opcode, params, output",
    [
        (o(EVM.PUSH0), [], BV(0)),
        (o(EVM.ADD), [x, y], x.add(y)),
        (o(EVM.MUL), [x, y], x.mul(y, abstraction=f_mul[x.size])),
        (o(EVM.SUB), [x, y], x.sub(y)),
        (o(EVM.DIV), [x, y], x.div(y, abstraction=f_div)),
        (o(EVM.DIV), [BV(5), BV(3)], BV(1)),
        (o(EVM.DIV), [x, BV(0)], BV(0)),
        (o(EVM.DIV), [x, BV(1)], x),
        (o(EVM.DIV), [x, BV(2**3)], BV(LShR(x.as_z3(), 3))),
        (o(EVM.SDIV), [x, y], x.sdiv(y, abstraction=f_sdiv)),
        (o(EVM.SDIV), [BV(5), BV(3)], BV(1)),
        (o(EVM.SDIV), [BV(-5), BV(3)], BV(-1)),
        (o(EVM.SDIV), [BV(5), BV(-3)], BV(-1)),
        (o(EVM.SDIV), [BV(-5), BV(-3)], BV(1)),
        (o(EVM.SDIV), [BV(-(2**255)), BV(-1)], BV(-(2**255))),  # overflow
        (o(EVM.SDIV), [BV(-(2**255)), BV(-1)], BV(2**255)),  # overflow
        (o(EVM.MOD), [x, y], x.mod(y, abstraction=f_mod[x.size])),
        (o(EVM.MOD), [BV(5), BV(3)], BV(2)),
        (o(EVM.MOD), [x, BV(0)], BV(0)),
        (o(EVM.MOD), [x, BV(1)], BV(0)),
        (o(EVM.MOD), [x, BV(2**3)], BV(ZeroExt(253, Extract(2, 0, x.as_z3())))),
        (
            o(EVM.SMOD),
            [x, y],
            x.smod(y, abstraction=f_smod),
        ),  # sdiv(x,y) * y + smod(x,y) == x
        (o(EVM.SMOD), [BV(5), BV(3)], BV(2)),
        (o(EVM.SMOD), [BV(-5), BV(3)], BV(-2)),
        (o(EVM.SMOD), [BV(5), BV(-3)], BV(2)),
        (o(EVM.SMOD), [BV(-5), BV(-3)], BV(-2)),
        (o(EVM.SMOD), [x, BV(0)], BV(0)),
        (o(EVM.SMOD), [x, BV(1)], BV(0)),
        (o(EVM.ADDMOD), [BV(4), BV(1), BV(3)], BV(2)),
        (o(EVM.ADDMOD), [x, y, BV(0)], BV(0)),
        (o(EVM.ADDMOD), [x, y, BV(1)], BV(0)),
        (
            o(EVM.ADDMOD),
            [x, y, BV(2**3)],
            BV(
                ZeroExt(
                    253,
                    Extract(2, 0, ZeroExt(8, x.as_z3()) + ZeroExt(8, y.as_z3())),
                )
            ),
        ),
        (
            o(EVM.ADDMOD),
            [x, y, z],
            BV(
                Extract(
                    255,
                    0,
                    f_mod[264](
                        ZeroExt(8, x.as_z3()) + ZeroExt(8, y.as_z3()),
                        ZeroExt(8, z.as_z3()),
                    ),
                )
            ),
        ),
        (o(EVM.ADDMOD), [BV(10), BV(10), BV(8)], BV(4)),
        (
            o(EVM.ADDMOD),
            [
                BV(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
                BV(2),
                BV(2),
            ],
            BV(1),
        ),
        (o(EVM.MULMOD), [BV(5), BV(1), BV(3)], BV(2)),
        (o(EVM.MULMOD), [x, y, BV(0)], BV(0)),
        (o(EVM.MULMOD), [x, y, BV(1)], BV(0)),
        (
            o(EVM.MULMOD),
            [x, y, BV(2**3)],
            BV(
                ZeroExt(
                    253,
                    Extract(
                        2,
                        0,
                        f_mul[512](ZeroExt(256, x.as_z3()), ZeroExt(256, y.as_z3())),
                    ),
                )
            ),
        ),
        (
            o(EVM.MULMOD),
            [x, y, z],
            BV(
                Extract(
                    255,
                    0,
                    f_mod[512](
                        f_mul[512](ZeroExt(256, x.as_z3()), ZeroExt(256, y.as_z3())),
                        ZeroExt(256, z.as_z3()),
                    ),
                )
            ),
        ),
        (o(EVM.MULMOD), [BV(10), BV(10), BV(8)], BV(4)),
        (
            o(EVM.MULMOD),
            [
                BV(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
                BV(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF),
                BV(12),
            ],
            BV(9),
        ),
        (o(EVM.EXP), [x, y], x.exp(y, exp_abstraction=f_exp)),
        (o(EVM.EXP), [x, BV(0)], BV(1)),
        (o(EVM.EXP), [x, BV(1)], x),
        (o(EVM.EXP), [x, BV(2)], x.mul(x, abstraction=f_mul[x.size])),
        (o(EVM.SIGNEXTEND), [BV(0), BV(0xFF)], BV(-1)),
        (o(EVM.SIGNEXTEND), [BV(0), y], BV(SignExt(248, Extract(7, 0, y.as_z3())))),
        (o(EVM.SIGNEXTEND), [BV(1), y], BV(SignExt(240, Extract(15, 0, y.as_z3())))),
        (o(EVM.SIGNEXTEND), [BV(30), y], BV(SignExt(8, Extract(247, 0, y.as_z3())))),
        (o(EVM.SIGNEXTEND), [BV(31), y], y),
        (o(EVM.SIGNEXTEND), [BV(32), y], y),
        (o(EVM.SIGNEXTEND), [BV(33), y], y),
        (o(EVM.SIGNEXTEND), [BV(2**256 - 1), y], y),
        (o(EVM.LT), [x, y], x.ult(y)),
        (o(EVM.GT), [x, y], x.ugt(y)),
        (o(EVM.SLT), [x, y], x.slt(y)),
        (o(EVM.SGT), [x, y], x.sgt(y)),
        (o(EVM.EQ), [x, y], x.eq(y)),
        (o(EVM.ISZERO), [x], x.is_zero()),
        (o(EVM.AND), [x, y], x.bitwise_and(y)),
        (o(EVM.OR), [x, y], x.bitwise_or(y)),
        (o(EVM.XOR), [x, y], x.bitwise_xor(y)),
        (o(EVM.NOT), [x], x.bitwise_not()),
        (o(EVM.BYTE), [BV(0), BV_1234000000dcba], BV(0x11)),
        (o(EVM.BYTE), [BV(1), BV_1234000000dcba], BV(0x22)),
        (o(EVM.BYTE), [BV(30), BV_1234000000dcba], BV(0xBB)),
        (o(EVM.BYTE), [BV(31), BV_1234000000dcba], BV(0xAA)),
        (o(EVM.BYTE), [BV(32), BV_1234000000dcba], BV(0)),
        (o(EVM.BYTE), [BV(2**256 - 1), BV_1234000000dcba], BV(0)),
        (o(EVM.BYTE), [BV(0), y], BV(ZeroExt(248, Extract(255, 248, y.as_z3())))),
        (o(EVM.BYTE), [BV(1), y], BV(ZeroExt(248, Extract(247, 240, y.as_z3())))),
        (o(EVM.BYTE), [BV(31), y], BV(ZeroExt(248, Extract(7, 0, y.as_z3())))),
        (o(EVM.BYTE), [BV(32), y], BV(0)),
        (o(EVM.BYTE), [BV(33), y], BV(0)),
        (o(EVM.BYTE), [BV(2**256 - 1), y], BV(0)),
        (o(EVM.BYTE), [x, y], BV(byte_of(x.as_z3(), y.as_z3()))),
        (o(EVM.SHL), [x, y], y.lshl(x)),
        (o(EVM.SHL), [BV(0), y], y),
        (o(EVM.SHL), [BV(255), y], y.lshl(BV(255))),
        (o(EVM.SHL), [BV(256), y], BV(0)),
        (o(EVM.SHL), [BV(2**256 - 1), y], BV(0)),
        (o(EVM.SHR), [x, y], y.lshr(x)),
        (o(EVM.SHR), [BV(0), y], y),
        (o(EVM.SHR), [BV(255), y], y.lshr(BV(255))),
        (o(EVM.SHR), [BV(256), y], BV(0)),
        (o(EVM.SHR), [BV(2**256 - 1), y], BV(0)),
        (o(EVM.SAR), [x, y], y.ashr(x)),
        (o(EVM.SAR), [BV(0), y], y),
        (o(EVM.SAR), [BV(255), y], y.ashr(BV(255))),
        (
            o(EVM.SAR),
            [BV(256), y],
            y.ashr(BV(256)),
        ),  # not necessarily 0; TODO: prove it is equal to y >> 255
        (
            o(EVM.SAR),
            [BV(2**256 - 1), y],
            y.ashr(BV(2**256 - 1)),
        ),  # not necessarily 0; TODO: prove it is equal to y >> 255
        # TODO: SHA3
        (o(EVM.ADDRESS), [], uint256(this)),
        (o(EVM.BALANCE), [x], BV(Select(balance, uint160(x).as_z3()))),
        (o(EVM.ORIGIN), [], uint256(origin)),
        (o(EVM.CALLER), [], uint256(caller)),
        (o(EVM.CALLVALUE), [], BV(callvalue)),
        # TODO: CALLDATA*, CODE*, EXTCODE*, RETURNDATA*, CREATE*
        (o(EVM.SELFBALANCE), [], BV(Select(balance, this))),
    ],
)
def test_opcode_simple(opcode, params, output, sevm: SEVM, solver, storage):
    ex = mk_ex(Concat(opcode, o(EVM.STOP)), sevm, solver, storage, caller, this)

    # reversed because in the tests the stack is written with the top on the left
    # but in the internal state, the top of the stack is the last element of the list
    ex.st.stack.extend(reversed(params))
    exs: list[Exec] = list(sevm.run(ex))

    [output_ex] = exs
    assert output_ex.st.stack.pop() == output


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


@pytest.mark.parametrize(
    "opcode",
    [
        EVM.POP,
        *range(EVM.DUP1, EVM.DUP16 + 1),
        *range(EVM.SWAP1, EVM.SWAP16 + 1),
    ],
)
def test_stack_underflow(sevm: SEVM, solver, storage, opcode):
    """Test that operations on empty stack raise StackUnderflowError"""
    ex = mk_ex(o(opcode), sevm, solver, storage, caller, this)
    [output_ex] = list(sevm.run(ex))
    assert isinstance(output_ex.context.output.error, StackUnderflowError)


def test_large_memory_offset(sevm: SEVM, solver, storage):
    for op in [o(EVM.MLOAD), o(EVM.MSTORE), o(EVM.MSTORE8)]:
        ex = mk_ex(op, sevm, solver, storage, caller, this)
        ex.st.stack.append(con(42))  # value, ignored by MLOAD
        ex.st.stack.append(con(2**64))  # offset too big to fit in memory

    exs: list[Exec] = list(sevm.run(ex))

    [output_ex] = exs
    assert isinstance(output_ex.context.output.error, OutOfGasError)


def test_jump_into_push_data(sevm, solver, storage):
    hexcode = bytes.fromhex("60055663015b000000")  # PUSH1 0x05; JUMP; PUSH4 0x015B0000;

    exec = mk_ex(hexcode, sevm, solver, storage, caller, this)

    execs = list(sevm.run(exec))

    # Ensure execution halted due to an invalid jump
    assert len(execs) == 1  # Only one execution path should exist
    assert execs[0].context.output.error is not None  # Ensure an error occurred
    assert isinstance(
        execs[0].context.output.error, InvalidJumpDestError
    )  # Check correct error type


def test_jumpi_false_condition_no_error(sevm, solver, storage):
    hexcode = bytes.fromhex(
        "6000600657005BFE"
    )  # PUSH1 0x00; PUSH1 0x06; JUMPI; STOP; JUMPDEST; INVALID;
    exec = mk_ex(hexcode, sevm, solver, storage, caller, this)

    execs = list(sevm.run(exec))  # Execution should continue without error
    assert len(execs) == 1
    assert execs[0].pc == 5  # PC should proceed to STOP without jumping


def test_jumpi_false_condition_INVALID_error(sevm, solver, storage):
    hexcode = bytes.fromhex(
        "6000600657FE5B00"
    )  # PUSH1 0x00; PUSH1 0x06; JUMPI; INVALID; JUMPDEST; STOP;
    exec = mk_ex(hexcode, sevm, solver, storage, caller, this)

    execs = list(sevm.run(exec))  # Execution should continue without error
    assert len(execs) == 1
    assert (
        execs[0].context.output.error is not None
    )  # Verify execution halted with an error
    assert isinstance(
        execs[0].context.output.error, InvalidOpcode
    )  # Ensure the correct error type was raised (PC did not jump, hence InvalidOpcode error is raised)


def test_invalid_jumpi(sevm, solver, storage):
    hexcode = bytes.fromhex("6001600557FE")  # PUSH1 0x01; PUSH1 0x05; JUMPI; INVALID;
    exec = mk_ex(hexcode, sevm, solver, storage, caller, this)

    execs = list(sevm.run(exec))

    assert len(execs) == 1  # Ensure only one execution path exists
    assert (
        execs[0].context.output.error is not None
    )  # Verify execution halted with an error
    assert isinstance(
        execs[0].context.output.error, InvalidJumpDestError
    )  # Ensure the correct error type was raised (PC did jump, hence InvalidJumpDestError error is raised)


def test_valid_jumpi(sevm, solver, storage):
    hexcode = bytes.fromhex(
        "60016005575B00"
    )  # PUSH1 0x01; PUSH1 0x05; JUMPI; JUMPDEST;  STOP;
    exec = mk_ex(hexcode, sevm, solver, storage, caller, this)

    execs = list(sevm.run(exec))

    assert len(execs) == 1  # Ensure only one execution path exists
    assert execs[0].pc == 6  # PC should move to the stop
    assert execs[0].current_opcode() == EVM.STOP  # Should terminate cleanly


def test_invalid_jump(sevm, solver, storage):
    hexcode = bytes.fromhex(
        "60035601"
    )  # PUSH1 0x03; JUMP; ADD; (but no JUMPDEST at 0x03)
    exec = mk_ex(hexcode, sevm, solver, storage, caller, this)

    execs = list(sevm.run(exec))

    assert len(execs) == 1  # Ensure only one execution path exists
    assert (
        execs[0].context.output.error is not None
    )  # Verify execution halted with an error
    assert isinstance(
        execs[0].context.output.error, InvalidJumpDestError
    )  # Ensure the correct error type was raised


def test_valid_jump(sevm, solver, storage):
    hexcode = bytes.fromhex("6003565B00")  # PUSH1 0x03; JUMP; JUMPDEST; STOP
    exec = mk_ex(hexcode, sevm, solver, storage, caller, this)
    execs = list(sevm.run(exec))

    assert len(execs) == 1  # Only one valid path should execute
    assert execs[0].pc == 4  # PC should move to the stop
    assert execs[0].current_opcode() == EVM.STOP  # Should terminate cleanly
