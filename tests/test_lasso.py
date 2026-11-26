import json
import os
import shutil
import subprocess

import pytest
from z3 import UGE, ULT, BitVec, BitVecVal, simplify

from dolmos.lasso import (
    MAX_SMALL_CONSTANT,
    BodyPath,
    LassoError,
    Registry,
    Translator,
    WrapProver,
    build_lasso,
    check_small_constants,
)

M = 2**256


def v(name: str):
    return BitVec(f"lasso_v1_{name}", 256)


def small_translator(conditions, names=None):
    prover = WrapProver(conditions, 1000)
    return Translator(Registry(), names or {}, stem=False, prover=prover)


def test_add_without_wrap_is_exact():
    x = v("x")
    tr = small_translator([ULT(x, 100)], {"lasso_v1_x": "x_i"})
    assert tr.bv(x + 1) == "(+ x_i 1)"
    assert not tr.reg.approximate


def test_add_with_possible_wrap_is_approximated():
    x = v("x")
    tr = small_translator([], {"lasso_v1_x": "x_i"})
    r = tr.bv(x + 1)
    assert r.startswith("aux")
    assert f"(<= {r} (+ x_i 1))" in tr.constraints
    assert tr.reg.approximate


def test_minus_one_is_a_subtraction():
    # solc compiles x - 1 as x + (2^256 - 1)
    x = v("x")
    expr = simplify(x - 1)
    tr = small_translator([UGE(x, 1)], {"lasso_v1_x": "x_i"})
    assert tr.bv(expr) == "(- x_i 1)"


def test_borrow_without_large_constant():
    x = v("x")
    tr = small_translator([], {"lasso_v1_x": "x_i"})
    r = tr.bv(simplify(x - 2))
    assert any("(< (- x_i 2) 0)" in c for c in tr.constraints)
    for c in tr.constraints:
        check_small_constants(c)
    assert r.startswith("aux")


def test_large_literals_become_constants():
    x = v("x")
    tr = small_translator([], {"lasso_v1_x": "x_i"})
    term = tr.bv(x & BitVecVal(0xFF << 200, 256))  # not a low mask: opaque
    tr2 = small_translator([], {"lasso_v1_x": "x_i"})
    lit = tr2.bool(ULT(x, BitVecVal(2**200, 256)))
    assert lit == "(< x_i c0)"
    assert term
    assert tr2.reg.approximate


def test_exact_encoding_keeps_wrap_cases():
    x = v("x")
    tr = Translator(Registry(), {"lasso_v1_x": "x_i"}, stem=False)
    tr.bv(x + 1)
    assert any(str(M) in c for c in tr.constraints)


def test_check_small_constants():
    check_small_constants(f"(< x {MAX_SMALL_CONSTANT})")
    with pytest.raises(LassoError):
        check_small_constants(f"(< x {M})")


def count_down_lasso():
    # while (x != 0) { x -= 1; }   (checked arithmetic: x >= 1 on the path)
    x = v("0")
    out = simplify(x - 1)
    again = out != 0
    body = BodyPath(
        conditions=[UGE(x, 1), again],
        outputs=[out],
        context=[UGE(x, 1), again],
    )
    n = BitVec("p_n_uint256", 256)
    approximate, lasso = build_lasso(
        ["lasso_v1_0"],
        [256],
        [n],
        [n != 0],
        None,
        [body],
        stem_context=[n != 0],
        complete=True,
    )
    return approximate, lasso


def test_count_down_lasso():
    approximate, lasso = count_down_lasso()
    assert not approximate
    loop = lasso["loop"][0]
    assert "(= v0_o (- v0_i 1))" in loop["formula"]
    check_small_constants(loop["formula"])
    check_small_constants(lasso["stem"][0]["formula"])
    assert lasso["program_vars"] == ["v0"]


@pytest.mark.skipif(
    not (os.environ.get("PASTTEL") or shutil.which("pasttel")),
    reason="PaSTTeL binary not available (set PASTTEL)",
)
def test_count_down_terminates_with_pasttel(tmp_path):
    binary = os.environ.get("PASTTEL") or shutil.which("pasttel")
    _, lasso = count_down_lasso()
    path = tmp_path / "count_down.json"
    path.write_text(json.dumps(lasso))
    out = subprocess.run(
        [binary, "-a", "both", "-t", "30", str(path)],
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout
    assert "OVERALL RESULT: TERMINATING" in out
