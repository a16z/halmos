import pytest
import json

from z3 import *

from halmos.utils import EVM

from halmos.byte2op import decode

from halmos.sevm import SEVM, con, ops_to_pgm

from halmos.__main__ import parse_args

# TODO: test every opcode semantics

@pytest.fixture
def args():
    return parse_args([])

@pytest.fixture
def options(args):
    return {
        'verbose': args.verbose,
        'debug': args.debug,
        'log': args.log,
        'add': not args.no_smt_add,
        'sub': not args.no_smt_sub,
        'mul': not args.no_smt_mul,
        'div': args.smt_div,
        'divByConst': args.smt_div_by_const,
        'modByConst': args.smt_mod_by_const,
        'expByConst': args.smt_exp_by_const,
        'timeout': args.solver_timeout_branching,
    }

@pytest.fixture
def sevm(options):
    return SEVM(options)

@pytest.fixture
def solver(args):
    solver = SolverFor('QF_AUFBV') # quantifier-free bitvector + array theory; https://smtlib.cs.uiowa.edu/logics.shtml
    solver.set(timeout=args.solver_timeout_branching)
    return solver

@pytest.fixture
def storage():
    return {}

@pytest.fixture
def caller(solver):
    caller = BitVec('msg_sender', 256)
    solver.add(Extract(255, 160, caller) == BitVecVal(0, 96))
    return caller

@pytest.fixture
def this(solver):
    this = BitVec('this_address', 256)
    solver.add(Extract(255, 160, this) == BitVecVal(0, 96))
    return this

def mk_ex(hexcode, sevm, solver, storage, caller, this):
    (ops, code) = decode(hexcode)
    pgm = ops_to_pgm(ops)
    return sevm.mk_exec(
        pgm       = { this: pgm },
        code      = { this: code },
        storage   = { this: storage },
        balance   = { this: con(0) },
        calldata  = [],
        callvalue = con(0),
        caller    = caller,
        this      = this,
        symbolic  = True,
        solver    = solver,
    )

def test_run(sevm, solver, storage, caller, this):
    hexcode = BitVecVal(int('600100', 16), 24)
    ex = mk_ex(hexcode, sevm, solver, storage, caller, this)
    (exs, _) = sevm.run(ex)
    assert len(exs) == 1
    ex = exs[0]
    assert str(ex.st.stack) == '[1]'
    assert str(ex.pgm[ex.this][ex.pc].op[0]) == '0'

    hexcode = BitVec('x', 256)
    ex = mk_ex(hexcode, sevm, solver, storage, caller, this)
    (exs, _) = sevm.run(ex)
    assert len(exs) == 1
    ex = exs[0]
    assert str(ex.st.stack) == '[]'
    assert ex.pc == 0
    assert str(ex.pgm[ex.this][ex.pc].op[0]) == 'Extract(255, 248, x)'

    hexcode = Concat(BitVecVal(int('6001', 16), 16), BitVec('x', 8), BitVecVal(0, 8))
    ex = mk_ex(hexcode, sevm, solver, storage, caller, this)
    (exs, _) = sevm.run(ex)
    assert len(exs) == 1
    ex = exs[0]
    assert str(ex.st.stack) == '[1]'
    assert ex.pc == 2
    assert str(ex.pgm[ex.this][ex.pc].op[0]) == 'x'

    hexcode = Concat(BitVecVal(int('6101', 16), 16), BitVec('x', 8), BitVecVal(0, 8))
    ex = mk_ex(hexcode, sevm, solver, storage, caller, this)
    (exs, _) = sevm.run(ex)
    assert len(exs) == 1
    ex = exs[0]
    assert str(ex.st.stack) == '[Concat(1, x)]'
    assert str(ex.pgm[ex.this][ex.pc].op[0]) == '0'
