import pytest

from z3 import *

from halmos.utils import EVM

from halmos.sevm import con, Contract, f_div, f_sdiv, f_mod, f_smod, f_exp, f_origin, SEVM, Exec, int_of, uint256, uint160, iter_bytes, wload, wstore

from halmos.__main__ import mk_block

from test_fixtures import args, options, sevm

caller = BitVec('msg_sender', 160)

this = BitVec('this_address', 160)

balance = Array('balance_0', BitVecSort(160), BitVecSort(256))

callvalue = BitVec('msg_value', 256)

@pytest.fixture
def solver(args):
    solver = SolverFor('QF_AUFBV') # quantifier-free bitvector + array theory; https://smtlib.cs.uiowa.edu/logics.shtml
    solver.set(timeout=args.solver_timeout_branching)
    return solver

@pytest.fixture
def storage():
    return {}

def mk_ex(hexcode, sevm, solver, storage, caller, this):
    return sevm.mk_exec(
        code      = { this: Contract(hexcode) },
        storage   = { this: storage },
        balance   = balance,
        block     = mk_block(),
        calldata  = [],
        callvalue = callvalue,
        caller    = caller,
        this      = this,
        symbolic  = True,
        solver    = solver,
    )

x = BitVec('x', 256)
y = BitVec('y', 256)
z = BitVec('z', 256)

def o(opcode):
    return BitVecVal(opcode, 8)

@pytest.mark.parametrize('hexcode, stack, pc, opcode', [
    (BitVecVal(int('600100', 16), 24), '[1]', 2, EVM.STOP),

    # symbolic opcodes are not supported
    # (BitVec('x', 256), '[]', 0, 'Extract(255, 248, x)'),
    # (Concat(BitVecVal(int('6001', 16), 16), BitVec('x', 8), BitVecVal(0, 8)), '[1]', 2, 'x'),

    (Concat(BitVecVal(int('6101', 16), 16), BitVec('x', 8), BitVecVal(0, 8)), '[Concat(1, x)]', 3, EVM.STOP),
    (BitVecVal(int('58585B5860015800', 16), 64), '[6, 1, 3, 1, 0]', 7, EVM.STOP),
])
def test_run(hexcode, stack, pc, opcode: int, sevm, solver, storage):
    ex = mk_ex(hexcode, sevm, solver, storage, caller, this)
    (exs, _, _) = sevm.run(ex)
    assert len(exs) == 1
    ex: Exec = exs[0]
    assert str(ex.st.stack) == stack
    assert ex.pc == pc
    assert ex.current_opcode() == int_of(opcode)

def byte_of(i, x):
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

@pytest.mark.parametrize('hexcode, params, output', [
    (o(EVM.PUSH0), [], con(0)),
    (o(EVM.ADD), [x, y], x + y),
    (o(EVM.MUL), [x, y], x * y),
    (o(EVM.SUB), [x, y], x - y),
    (o(EVM.DIV), [x, y], f_div(x,y)),
    (o(EVM.DIV), [con(5), con(3)], con(1)),
    (o(EVM.DIV), [x, con(0)], con(0)),
    (o(EVM.DIV), [x, con(1)], x),
    (o(EVM.DIV), [x, con(2**3)], LShR(x, 3)),
    (o(EVM.SDIV), [x, y], f_sdiv(x,y)),
    (o(EVM.SDIV), [con(5), con(3)], con(1)),
    (o(EVM.SDIV), [con(-5), con(3)], con(-1)),
    (o(EVM.SDIV), [con(5), con(-3)], con(-1)),
    (o(EVM.SDIV), [con(-5), con(-3)], con(1)),
    (o(EVM.SDIV), [con(-2**255), con(-1)], con(-2**255)), # overflow
    (o(EVM.SDIV), [con(-2**255), con(-1)], con(2**255)), # overflow
    (o(EVM.MOD), [x, y], f_mod[x.size()](x,y)),
    (o(EVM.MOD), [con(5), con(3)], con(2)),
    (o(EVM.MOD), [x, con(0)], con(0)),
    (o(EVM.MOD), [x, con(1)], con(0)),
    (o(EVM.MOD), [x, con(2**3)], ZeroExt(253, Extract(2, 0, x))),
    (o(EVM.SMOD), [x, y], f_smod(x,y)), # sdiv(x,y) * y + smod(x,y) == x
    (o(EVM.SMOD), [con(5), con(3)], con(2)),
    (o(EVM.SMOD), [con(-5), con(3)], con(-2)),
    (o(EVM.SMOD), [con(5), con(-3)], con(2)),
    (o(EVM.SMOD), [con(-5), con(-3)], con(-2)),
    (o(EVM.ADDMOD), [con(4), con(1), con(3)], con(2)),
    (o(EVM.ADDMOD), [x, y, con(0)], con(0)),
    (o(EVM.ADDMOD), [x, y, con(1)], con(0)),
    (o(EVM.ADDMOD), [x, y, con(2**3)], ZeroExt(253, Extract(2, 0, ZeroExt(1, x) + ZeroExt(1, y)))),
    (o(EVM.ADDMOD), [x, y, z], Extract(255, 0, f_mod[257](ZeroExt(1, x) + ZeroExt(1, y), ZeroExt(1, z)))),
    (o(EVM.ADDMOD), [con(10), con(10), con(8)], con(4)),
    (o(EVM.ADDMOD), [con(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF), con(2), con(2)], con(1)),
    (o(EVM.MULMOD), [con(5), con(1), con(3)], con(2)),
    (o(EVM.MULMOD), [x, y, con(0)], con(0)),
    (o(EVM.MULMOD), [x, y, con(1)], con(0)),
    (o(EVM.MULMOD), [x, y, con(2**3)], ZeroExt(253, Extract(2, 0, ZeroExt(256, x) * ZeroExt(256, y)))),
    (o(EVM.MULMOD), [x, y, z], Extract(255, 0, f_mod[512](ZeroExt(256, x) * ZeroExt(256, y), ZeroExt(256, z)))),
    (o(EVM.MULMOD), [con(10), con(10), con(8)], con(4)),
    (o(EVM.MULMOD), [con(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF), con(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF), con(12)], con(9)),
    (o(EVM.EXP), [x, y], f_exp(x,y)),
    (o(EVM.EXP), [x, con(0)], con(1)),
    (o(EVM.EXP), [x, con(1)], x),
    (o(EVM.EXP), [x, con(2)], x * x),
    (o(EVM.SIGNEXTEND), [con(0), y], SignExt(248, Extract(7, 0, y))),
    (o(EVM.SIGNEXTEND), [con(1), y], SignExt(240, Extract(15, 0, y))),
    (o(EVM.SIGNEXTEND), [con(30), y], SignExt(8, Extract(247, 0, y))),
    (o(EVM.SIGNEXTEND), [con(31), y], y),
    (o(EVM.SIGNEXTEND), [con(32), y], y),
    (o(EVM.SIGNEXTEND), [con(33), y], y),
    (o(EVM.SIGNEXTEND), [con(2**256-1), y], y),
    (o(EVM.LT), [x, y], ULT(x, y)),
    (o(EVM.GT), [x, y], UGT(x, y)),
    (o(EVM.SLT), [x, y], x < y),
    (o(EVM.SGT), [x, y], x > y),
    (o(EVM.EQ), [x, y], x == y),
    (o(EVM.ISZERO), [x], x == con(0)),
    (o(EVM.AND), [x, y], x & y),
    (o(EVM.OR), [x, y], x | y),
    (o(EVM.XOR), [x, y], x ^ y),
    (o(EVM.NOT), [x], ~ x),
    (o(EVM.BYTE), [con(0), y], ZeroExt(248, Extract(255, 248, y))),
    (o(EVM.BYTE), [con(1), y], ZeroExt(248, Extract(247, 240, y))),
    (o(EVM.BYTE), [con(31), y], ZeroExt(248, Extract(7, 0, y))),
    (o(EVM.BYTE), [con(32), y], con(0)),
    (o(EVM.BYTE), [con(33), y], con(0)),
    (o(EVM.BYTE), [con(2**256-1), y], con(0)),
    (o(EVM.BYTE), [x, y], byte_of(x, y)),
    (o(EVM.SHL), [x, y], y << x),
    (o(EVM.SHL), [con(0), y], y),
    (o(EVM.SHL), [con(255), y], y << con(255)),
    (o(EVM.SHL), [con(256), y], con(0)),
    (o(EVM.SHL), [con(2**256-1), y], con(0)),
    (o(EVM.SHR), [x, y], LShR(y, x)),
    (o(EVM.SHR), [con(0), y], y),
    (o(EVM.SHR), [con(255), y], LShR(y, con(255))),
    (o(EVM.SHR), [con(256), y], con(0)),
    (o(EVM.SHR), [con(2**256-1), y], con(0)),
    (o(EVM.SAR), [x, y], y >> x),
    (o(EVM.SAR), [con(0), y], y),
    (o(EVM.SAR), [con(255), y], y >> con(255)),
    (o(EVM.SAR), [con(256), y], y >> con(256)), # not necessarily 0; TODO: prove it is equal to y >> 255
    (o(EVM.SAR), [con(2**256-1), y], y >> con(2**256-1)), # not necessarily 0; TODO: prove it is equal to y >> 255
    # TODO: SHA3
    (o(EVM.ADDRESS), [], uint256(this)),
    (o(EVM.BALANCE), [x], Select(balance, uint160(x))),
    (o(EVM.ORIGIN), [], uint256(f_origin())),
    (o(EVM.CALLER), [], uint256(caller)),
    (o(EVM.CALLVALUE), [], callvalue),
    # TODO: CALLDATA*, CODE*, EXTCODE*, RETURNDATA*, CREATE*
    (o(EVM.SELFBALANCE), [], Select(balance, this)),
])
def test_opcode_simple(hexcode, params, output, sevm: SEVM, solver, storage):
    ex = mk_ex(Concat(hexcode, o(EVM.STOP)), sevm, solver, storage, caller, this)
    ex.st.stack.extend(params)
    (exs, _, _) = sevm.run(ex)
    assert len(exs) == 1
    ex = exs[0]
    assert ex.st.stack[0] == simplify(output)

def test_stack_underflow_pop(sevm: SEVM, solver, storage):
    # check that we get an exception when popping from an empty stack
    ex = mk_ex(o(EVM.POP), sevm, solver, storage, caller, this)

    # TODO: from the outside, we should get an execution with failed=True
    # TODO: from the outside, we should get an specific exception like StackUnderflowError
    with pytest.raises(Exception):
        sevm.run(ex)

def test_iter_bytes_bv_val():
    b = BitVecVal(0x12345678, 32)
    assert list(iter_bytes(b)) == [0x12, 0x34, 0x56, 0x78]

def test_iter_bytes_bv_ref():
    x = BitVec('x', 8)
    b = Concat(BitVecVal(0x123456, 24), x)
    assert list(iter_bytes(b)) == [0x12, 0x34, 0x56, x]

def test_iter_bytes_int():
    # can not iterate bytes of an integer without explicit size
    with pytest.raises(Exception):
        list(iter_bytes(0x12345678))

    assert list(iter_bytes(0x12345678, _byte_length=4)) == [0x12, 0x34, 0x56, 0x78]
    assert list(iter_bytes(0x12345678, _byte_length=6)) == [0x00, 0x00, 0x12, 0x34, 0x56, 0x78]

def test_wload_wrong_type():
    with pytest.raises(ValueError):
        wload([bytes.fromhex("aa")], 0, 4)

def test_wload_concrete():
    # using ints or concrete bitvector values should be equivalent
    assert wload([0x12, 0x34, 0x56, 0x78], 0, 4, prefer_concrete=True) == bytes.fromhex("12345678")
    assert wload([0x12, 0x34, 0x56, 0x78], 0, 4, prefer_concrete=False) == con(0x12345678, 32)
    assert wload([con(x, 8) for x in [0x12, 0x34, 0x56, 0x78]], 0, 4, prefer_concrete=True) == bytes.fromhex("12345678")
    assert wload([con(x, 8) for x in [0x12, 0x34, 0x56, 0x78]], 0, 4, prefer_concrete=False) == con(0x12345678, 32)

def test_wload_symbolic():
    x = BitVec('x', 32)
    mem = []
    wstore(mem, 0, 4, x)

    assert wload(mem, 0, 4, prefer_concrete=False) == x

    # no effect because the memory is not concrete
    assert wload(mem, 0, 4, prefer_concrete=True) == x

def test_wload_bad_byte():
    with pytest.raises(ValueError):
        wload([512], 0, 1, prefer_concrete=True)

    with pytest.raises(ValueError):
        wload([512], 0, 1, prefer_concrete=False)
