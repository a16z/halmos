import pytest

from z3 import *

from halmos.utils import EVM

from halmos.sevm import con, Contract, f_div, f_sdiv, f_mod, f_smod, f_exp, f_origin, SEVM, Exec, int_of

from halmos.__main__ import mk_block

from test_fixtures import args, options, sevm

caller = BitVec('msg_sender', 256)

this = BitVec('this_address', 256)

balance = Array('balance0', BitVecSort(256), BitVecSort(256))

callvalue = BitVec('msg_value', 256)

@pytest.fixture
def solver(args):
    solver = SolverFor('QF_AUFBV') # quantifier-free bitvector + array theory; https://smtlib.cs.uiowa.edu/logics.shtml
    solver.set(timeout=args.solver_timeout_branching)
    solver.add(Extract(255, 160, caller) == BitVecVal(0, 96))
    solver.add(Extract(255, 160, this) == BitVecVal(0, 96))
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
    (exs, _) = sevm.run(ex)
    assert len(exs) == 1
    ex: Exec = exs[0]
    assert str(ex.st.stack) == stack
    assert ex.pc == pc
    assert ex.current_opcode() == int_of(opcode)

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
    (o(EVM.MOD), [x, y], f_mod(x,y)),
    (o(EVM.MOD), [con(5), con(3)], con(2)),
    (o(EVM.MOD), [x, con(0)], con(0)),
    (o(EVM.MOD), [x, con(1)], con(0)),
    (o(EVM.MOD), [x, con(2**3)], ZeroExt(253, Extract(2, 0, x))),
    (o(EVM.SMOD), [x, y], f_smod(x,y)), # sdiv(x,y) * y + smod(x,y) == x
    (o(EVM.SMOD), [con(5), con(3)], con(2)),
    (o(EVM.SMOD), [con(-5), con(3)], con(-2)),
    (o(EVM.SMOD), [con(5), con(-3)], con(2)),
    (o(EVM.SMOD), [con(-5), con(-3)], con(-2)),
    # TODO: ADDMOD
    # TODO: MULMOD
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
    (o(EVM.ADDRESS), [], this),
    (o(EVM.BALANCE), [x], Select(balance, x)),
    (o(EVM.ORIGIN), [], f_origin()),
    (o(EVM.CALLER), [], caller),
    (o(EVM.CALLVALUE), [], callvalue),
    # TODO: CALLDATA*, CODE*, EXTCODE*, RETURNDATA*, CREATE*
    (o(EVM.SELFBALANCE), [], Select(balance, this)),
])
def test_opcode_simple(hexcode, params, output, sevm: SEVM, solver, storage):
    ex = mk_ex(Concat(hexcode, o(EVM.STOP)), sevm, solver, storage, caller, this)
    ex.st.stack.extend(params)
    (exs, _) = sevm.run(ex)
    assert len(exs) == 1
    ex = exs[0]
    assert ex.st.stack[0] == simplify(output)
