import pytest
from eth_hash.auto import keccak
from z3 import sat, unknown, unsat

from dolmos.solve import (
    ModelVariable,
    keccak_fact,
    parse_model_str,
    parse_sha3_arg_values,
    sha3_arg_decls,
)


@pytest.mark.parametrize(
    "full_name",
    [
        "dolmos_y_uint256_043cfd7_01",
        "p_y_uint256_043cfd7_01",
    ],
)
def test_smtlib_z3_bv_output(full_name):
    smtlib_str = f"""
        (define-fun {full_name} () (_ BitVec 256)
        #x0000000000000000000000000000000000000000000000000000000000000000)
    """
    model = parse_model_str(smtlib_str)

    assert model[full_name] == ModelVariable(
        full_name=full_name,
        variable_name="y",
        solidity_type="uint256",
        smt_type="BitVec 256",
        size_bits=256,
        value=0,
    )


# note that yices only produces output like this with --smt2-model-format
# otherwise we get something like (= x #b00000100)
@pytest.mark.parametrize(
    "full_name",
    [
        "dolmos_z_uint256_cabf047_02",
        "p_z_uint256_cabf047_02",
    ],
)
def test_smtlib_yices_binary_output(full_name):
    smtlib_str = f"""
    (define-fun
        {full_name}
        ()
        (_ BitVec 256)
        #b1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)
    """
    model = parse_model_str(smtlib_str)
    assert model[full_name] == ModelVariable(
        full_name=full_name,
        variable_name="z",
        solidity_type="uint256",
        smt_type="BitVec 256",
        size_bits=256,
        value=1 << 255,
    )


@pytest.mark.parametrize(
    "full_name",
    [
        "dolmos_z_uint256_11ce021_08",
        "p_z_uint256_11ce021_08",
    ],
)
def test_smtlib_yices_decimal_output(full_name):
    val = 57896044618658097711785492504343953926634992332820282019728792003956564819968
    smtlib_str = f"""
        (define-fun {full_name} () (_ BitVec 256) (_ bv{val} 256))
    """
    model = parse_model_str(smtlib_str)
    assert model[full_name] == ModelVariable(
        full_name=full_name,
        variable_name="z",
        solidity_type="uint256",
        smt_type="BitVec 256",
        size_bits=256,
        value=val,
    )


@pytest.mark.parametrize(
    "full_name",
    [
        "dolmos_x_uint8_043cfd7_01",
        "p_x_uint8_043cfd7_01",
    ],
)
def test_smtlib_stp_output(full_name):
    # we should tolerate:
    # - the extra (model) command
    # - duplicate variable names
    # - the initial `sat` result
    # - the `|` around the variable name
    # - the space in `( define-fun ...)`
    smtlib_str = f"""
        sat
        (model
        ( define-fun |{full_name}| () (_ BitVec 8) #x04 )
        )
        (model
        ( define-fun |{full_name}| () (_ BitVec 8) #x04 )
        )
    """
    model = parse_model_str(smtlib_str)
    assert model[full_name] == ModelVariable(
        full_name=full_name,
        variable_name="x",
        solidity_type="uint8",
        smt_type="BitVec 8",
        size_bits=8,
        value=4,
    )


@pytest.mark.parametrize(
    "smtlib_str",
    [
        # z3
        "(define-fun sha3arg_0 () (_ BitVec 256)\n  #x000000000000000000000000000000000000000000000000000000000000002a)"
        "(define-fun sha3arg_1 () (_ BitVec 16) #x0001)",
        # yices --smt2-model-format --bvconst-in-decimal
        "(define-fun sha3arg_0 () (_ BitVec 256) (_ bv42 256))"
        "(define-fun sha3arg_1 () (_ BitVec 16) (_ bv1 16))",
        # yices --smt2-model-format
        "(define-fun sha3arg_0 () (_ BitVec 256) #b" + "0" * 250 + "101010)"
        "(define-fun sha3arg_1 () (_ BitVec 16) #b0000000000000001)",
    ],
)
def test_parse_sha3_arg_values(smtlib_str):
    values = parse_sha3_arg_values(
        "sat\n(define-fun p_x_uint256_00 () (_ BitVec 256) (_ bv7 256))\n" + smtlib_str
    )
    assert values == {0: (256, 42), 1: (16, 1)}


def test_keccak_fact():
    fact, hash_value = keccak_fact(256, 42)
    expected = int.from_bytes(keccak((42).to_bytes(32, "big")), "big")
    assert hash_value == expected
    assert fact == f"(assert (= (f_sha3_256 (_ bv42 256)) (_ bv{expected} 256)))\n"


def test_sha3_arg_decls():
    decls = sha3_arg_decls(((256, "p_x_uint256_00"), (512, "(concat a b)")))
    assert decls == (
        "(declare-fun sha3arg_0 () (_ BitVec 256))\n"
        "(assert (= sha3arg_0 p_x_uint256_00))\n"
        "(declare-fun sha3arg_1 () (_ BitVec 512))\n"
        "(assert (= sha3arg_1 (concat a b)))\n"
    )


def _refine_keccak_setup(tmp_path, monkeypatch, refined_results):
    """runs refine_keccak on a sat model whose keccak preimage is 0, with mocked solver results"""
    import dolmos.solve as solve_mod
    from dolmos.config import default_config
    from dolmos.sevm import SMTQuery
    from dolmos.solve import PathContext, PotentialModel, SolverOutput, SolvingContext

    ctx = PathContext(
        args=default_config(),
        path_id=0,
        solving_ctx=SolvingContext(dump_dir=tmp_path),
        query=SMTQuery("", []),
        sha3_args=((256, "p_x_uint256_00"),),
    )

    def mk_output(result, index):
        query_file = str(tmp_path / f"{index}.smt2")
        with open(f"{query_file}.out", "w") as f:
            f.write(f"(define-fun sha3arg_0 () (_ BitVec 256) (_ bv{index} 256))\n")
        model = PotentialModel(model={}, is_valid=True) if result == sat else None
        return SolverOutput(result, 0, 0, query_file, model=model)

    outputs = iter(mk_output(r, i + 1) for i, r in enumerate(refined_results))
    monkeypatch.setattr(solve_mod, "solve_low_level", lambda _ctx: next(outputs))
    return solve_mod.refine_keccak(ctx, mk_output(sat, 0))


def test_refine_keccak_unsat(tmp_path, monkeypatch):
    # the refined query is unsat: no counterexample under the real keccak values
    assert _refine_keccak_setup(tmp_path, monkeypatch, [unsat]).result == unsat


def test_refine_keccak_undecided_keeps_counterexample(tmp_path, monkeypatch):
    # the refined query times out: the counterexample is kept, as potentially invalid
    out = _refine_keccak_setup(tmp_path, monkeypatch, [unknown])
    assert out.result == sat
    assert not out.model.is_valid


def test_refine_keccak_rounds_exhausted(tmp_path, monkeypatch):
    # every round picks a new preimage: potentially invalid after the last round
    out = _refine_keccak_setup(tmp_path, monkeypatch, [sat, sat, sat])
    assert out.result == sat
    assert not out.model.is_valid


def _sha3_term(data):
    from z3 import BitVecSort, Function

    return Function(f"f_sha3_{data.size()}", BitVecSort(data.size()), BitVecSort(256))(
        data
    )


def test_mk_keccak_facts():
    from z3 import BitVec, BitVecVal, Concat, ZeroExt

    from dolmos.solve import mk_keccak_facts

    x8 = BitVec("x8", 8)
    small = _sha3_term(ZeroExt(248, x8))  # keccak256(abi.encode(uint8))
    large = _sha3_term(BitVec("x256", 256))
    slot = _sha3_term(Concat(ZeroExt(255, BitVec("flag", 1)), BitVecVal(3, 256)))
    sha3s = [small, large, slot, _sha3_term(BitVecVal(1, 256))]

    assert mk_keccak_facts(sha3s, 0) == ""
    assert mk_keccak_facts([large], 8) == ""

    facts = mk_keccak_facts(sha3s, 8)
    assert facts.count("(=> ") == 256 + 2
    assert "(declare-fun sha3dom_0 () (_ BitVec 256))" in facts
    assert "(assert (= sha3img_1 (f_sha3_512 " in facts
    assert (
        f"(assert (=> (= ((_ extract 7 0) sha3dom_0) (_ bv42 8)) (= sha3img_0 (_ bv{keccak_fact(256, 42)[1]} 256))))"
        in facts
    )
    assert (
        f"(assert (=> (= ((_ extract 256 256) sha3dom_1) (_ bv1 1)) (= sha3img_1 (_ bv{keccak_fact(512, (1 << 256) | 3)[1]} 256))))"
        in facts
    )

    # only the preimages with at most 1 free bit
    assert mk_keccak_facts(sha3s, 1).count("(=> ") == 2


def test_mk_keccak_facts_split_domain():
    """free bits that are not contiguous are compared run by run"""
    from z3 import BitVec, BitVecVal, Concat

    from dolmos.solve import mk_keccak_facts

    a, b = BitVec("a", 1), BitVec("b", 2)
    data = Concat(a, BitVecVal(0x5, 5), b, BitVecVal(0, 248))
    facts = mk_keccak_facts([_sha3_term(data)], 8)
    assert facts.count("(=> ") == 8
    value = (1 << 255) | (0x5 << 250) | (2 << 248)
    assert (
        "(assert (=> (and (= ((_ extract 249 248) sha3dom_0) (_ bv2 2)) (= ((_ extract 255 255) sha3dom_0) (_ bv1 1))) "
        f"(= sha3img_0 (_ bv{keccak_fact(256, value)[1]} 256))))" in facts
    )


@pytest.mark.parametrize("split", [False, True])
def test_keccak_facts_make_the_query_exact(split):
    """with the facts, the uninterpreted hash of a small domain is the real keccak256"""
    from z3 import (
        BitVec,
        BitVecVal,
        Concat,
        Extract,
        Solver,
        ZeroExt,
        parse_smt2_string,
    )

    from dolmos.solve import mk_keccak_facts

    x8 = BitVec("x8", 8)
    if split:
        data = Concat(
            BitVecVal(0, 120), Extract(7, 4, x8), BitVecVal(0, 128), Extract(3, 0, x8)
        )
        preimage = (0xA << 132) | 0x7
    else:
        data = ZeroExt(248, x8)
        preimage = 0xA7
    term = _sha3_term(data)
    facts = mk_keccak_facts([term], 8)
    decls = (
        "(declare-fun f_sha3_256 ((_ BitVec 256)) (_ BitVec 256))\n"
        "(declare-fun x8 () (_ BitVec 8))\n"
    )

    def solver():
        s = Solver()
        s.add(parse_smt2_string(decls + facts))
        return s

    # the preimage of a real hash is found
    target = int.from_bytes(keccak(preimage.to_bytes(32, "big")), "big")
    s = solver()
    s.add(term == BitVecVal(target, 256))
    assert s.check() == sat
    assert s.model()[x8].as_long() == 0xA7

    # a value that is not the hash of a value of the domain is refuted, instead of being "found"
    s = solver()
    s.add(term == BitVecVal(target ^ 1, 256))
    assert s.check() == unsat


def test_solve_end_to_end_adds_keccak_facts(tmp_path, monkeypatch):
    import dolmos.solve as solve_mod
    from dolmos.config import default_config
    from dolmos.sevm import SMTQuery
    from dolmos.solve import PathContext, SolverOutput, SolvingContext

    fact = keccak_fact(256, 42)[0]
    ctx = PathContext(
        args=default_config(),
        path_id=0,
        solving_ctx=SolvingContext(dump_dir=tmp_path),
        query=SMTQuery("(query)\n", []),
        keccak_facts=fact,
    )
    assert ctx.refine().keccak_facts == fact

    seen = []

    def fake_solve(solved_ctx):
        seen.append(solved_ctx.query.smtlib)
        return SolverOutput(unsat, 0, 0, str(tmp_path / "0.smt2"), unsat_core=["1"])

    monkeypatch.setattr(solve_mod, "_solve_end_to_end", fake_solve)
    out = solve_mod.solve_end_to_end(ctx)
    assert seen == ["(query)\n" + fact]
    # the unsat core depends on the facts: it is not reusable
    assert out.result == unsat and out.unsat_core is None
