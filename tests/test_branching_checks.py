# SPDX-License-Identifier: AGPL-3.0

import z3

from dolmos.sevm import Path
from dolmos.utils import create_solver


def hard_condition():
    x, y = z3.BitVecs("hx hy", 256)
    return z3.And(x * x * y == 0x1234567, y * y * x == 0x7654321, z3.UGT(x, 1))


def test_path_check_retries_with_a_reduced_budget(monkeypatch):
    x = z3.BitVec("x", 256)
    solver = create_solver(timeout=100, retry_rlimit=100)
    path = Path(solver)
    path.append(x == 3)

    # definite answers are not recorded
    assert path.check(z3.UGT(x, 5)) == z3.unsat
    assert path.check(z3.ULT(x, 5)) == z3.sat
    assert not solver.unknown_conds

    # a condition that times out is recorded...
    cond = hard_condition()
    assert path.check(cond) == z3.unknown
    assert cond.get_id() in solver.unknown_conds

    # ... and checked again with the resource limit, which is reset afterwards
    limits = []
    original_set = solver.set
    monkeypatch.setattr(
        solver, "set", lambda **kw: (limits.append(kw), original_set(**kw))
    )
    assert path.check(cond) == z3.unknown
    assert limits == [{"rlimit": 100}, {"rlimit": 0}]

    # the other conditions still get the full budget, and the quick unsat is found
    # under the reduced budget too
    limits.clear()
    assert path.check(z3.UGT(x, 5)) == z3.unsat
    assert limits == []
    solver.unknown_conds[z3.UGT(x, 7).get_id()] = z3.UGT(x, 7)
    assert path.check(z3.UGT(x, 7)) == z3.unsat
    assert limits == [{"rlimit": 100}, {"rlimit": 0}]


def test_path_check_retry_can_be_disabled():
    for kwargs in (
        {"timeout": 1, "retry_rlimit": 0},
        {"timeout": 0, "retry_rlimit": 100},
    ):
        solver = create_solver(**kwargs)
        assert solver.retry_rlimit == 0

    solver = create_solver(timeout=100, retry_rlimit=0)
    path = Path(solver)
    assert path.check(hard_condition()) == z3.unknown
    assert not solver.unknown_conds


def test_branches_share_the_unknown_conditions():
    solver = create_solver(timeout=100, retry_rlimit=100)
    path = Path(solver)
    cond = hard_condition()
    assert path.check(cond) == z3.unknown

    branch = path.branch(z3.BitVec("x", 256) == 1)
    assert branch.solver.unknown_conds is solver.unknown_conds
    assert cond.get_id() in branch.solver.unknown_conds
