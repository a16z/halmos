import signal
from types import SimpleNamespace

from dolmos.solve import describe_solver_error


def test_describe_solver_error_signal():
    args = SimpleNamespace(solver_command=None, solver="yices")
    msg = describe_solver_error("", -signal.SIGILL, args)
    assert "SIGILL" in msg
    assert "illegal instruction" in msg
    assert "solver: yices" in msg

    msg = describe_solver_error("out of memory", -signal.SIGKILL, args)
    assert "SIGKILL" in msg and "stderr: out of memory" in msg


def test_describe_solver_error_exit_code():
    assert describe_solver_error("boom", 3) == "solver exited with code 3; stderr: boom"
    assert describe_solver_error("", 0) == "unexpected solver output"
