import pytest
from z3 import BitVec, Context, Solver, sat, unsat

from halmos.config import ConfigSource, default_config
from halmos.sevm import Path


@pytest.mark.parametrize("cache_solver", [False, True])
def test_serialization_includes_sliced_constraints_without_mutating_solver(
    cache_solver,
):
    ctx = Context()
    solver = Solver(ctx=ctx)
    path = Path(solver)
    x = BitVec("serialize_x", 8, ctx)
    path.append(x == 1)
    path.append(x == 2)

    # An invariant's execution solver can contain fewer constraints than its path.
    solver.reset()
    solver.add(x == 2)
    solver.push()
    solver.add(x != 3)
    before = solver.sexpr()
    options = default_config().with_overrides(
        ConfigSource.command_line, cache_solver=cache_solver
    )

    for _ in range(2):
        query = path.to_smt2(options)
        reader = Solver()
        reader.from_string(query.smtlib)
        if cache_solver:
            reader.from_string("\n".join(f"(assert |{i}|)" for i in query.assertions))
        assert reader.check() == unsat
        assert solver.sexpr() == before
        assert solver.num_scopes() == 1
        assert solver.check() == sat

    # No assertions from the previous serialization may leak into another query.
    other = Path(Solver(ctx=ctx))
    other.append(x == 3)
    reader = Solver()
    query = other.to_smt2(options)
    reader.from_string(
        query.smtlib
        + (
            "\n".join(f"(assert |{i}|)" for i in query.assertions)
            if cache_solver
            else ""
        )
    )
    assert reader.check() == sat
