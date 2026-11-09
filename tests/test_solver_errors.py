from types import SimpleNamespace

from dolmos.solve import describe_solver_error

# the signal numbers are POSIX ones, used as such on every platform: the signal module
# lacks SIGKILL on Windows


def test_describe_solver_error_signal():
    args = SimpleNamespace(solver_command=None, solver="yices")
    msg = describe_solver_error("", -4, args)
    assert "SIGILL" in msg
    assert "illegal instruction" in msg
    assert "solver: yices" in msg

    msg = describe_solver_error("out of memory", -9, args)
    assert "SIGKILL" in msg and "stderr: out of memory" in msg

    assert "signal 42" in describe_solver_error("", -42)


def test_describe_solver_error_windows_exception():
    # unsigned, as reported by subprocess on Windows
    msg = describe_solver_error("", 0xC000001D)
    assert "STATUS_ILLEGAL_INSTRUCTION" in msg and "illegal instruction" in msg
    # signed 32-bit, as reported by some runtimes
    msg = describe_solver_error("", 0xC0000005 - 2**32)
    assert "STATUS_ACCESS_VIOLATION" in msg


def test_describe_solver_error_exit_code():
    assert describe_solver_error("boom", 3) == "solver exited with code 3; stderr: boom"
    assert describe_solver_error("", 0) == "unexpected solver output"
