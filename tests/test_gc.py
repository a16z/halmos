import gc

import pytest

import halmos.__main__ as cli


@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize("raise_error", [False, True])
def test_execution_defers_gc_and_restores_callers_policy(
    monkeypatch, enabled, raise_error
):
    previous = gc.isenabled()

    def execute(args, *, collect_garbage):
        assert not gc.isenabled()
        assert collect_garbage is enabled
        if raise_error:
            raise RuntimeError("failed execution")
        return cli.MainResult(0)

    monkeypatch.setattr(cli, "_main_impl", execute)
    try:
        (gc.enable if enabled else gc.disable)()
        if raise_error:
            with pytest.raises(RuntimeError, match="failed execution"):
                cli._main([])
        else:
            assert cli._main([]).exitcode == 0
        assert gc.isenabled() is enabled
    finally:
        (gc.enable if previous else gc.disable)()
