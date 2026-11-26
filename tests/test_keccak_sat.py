# SPDX-License-Identifier: AGPL-3.0

import itertools
import random
from pathlib import Path

import pytest
import z3
from eth_hash.auto import keccak

from dolmos.keccak_sat import (
    TEMPLATES,
    KeccakCNF,
    bits_to_bytes,
    bytes_to_bits,
    cofactor_cnf,
    cofactor_table,
    exhaustive_keccak_values,
    free_bits,
    keccak256,
    lean_templates,
    template_holds,
)

GATES = {
    "xor2": lambda a, b: a ^ b,
    "xor3": lambda a, b, c: a ^ b ^ c,
    "and": lambda a, b: a & b,
    "chi": lambda a, b, c: a ^ ((not b) & c),
}

LEAN_TEMPLATES = (
    Path(__file__).parent.parent / "proofs/keccak_sat/KeccakSat/Templates.lean"
)


@pytest.mark.parametrize("size", [0, 1, 32, 64, 135, 136, 137, 272, 300])
def test_reference_keccak256(size):
    data = random.Random(size).randbytes(size)
    assert keccak256(data) == keccak(data)


@pytest.mark.parametrize("name", TEMPLATES)
def test_templates(name):
    """each template holds exactly on the truth table of its gate"""
    cnf, _ = TEMPLATES[name]
    n = max(abs(lit) for clause in cnf for lit in clause)
    for values in itertools.product([False, True], repeat=n):
        expected = values[-1] == bool(GATES[name](*values[:-1]))
        assert template_holds(cnf, values) == expected


def test_lean_templates_in_sync():
    """the templates proved in Lean are the ones used by the encoder"""
    assert LEAN_TEMPLATES.read_text() == lean_templates()


@pytest.mark.parametrize("optimized", [True, False])
@pytest.mark.parametrize("size", [0, 32, 64, 135, 136, 200])
def test_cnf_constant_folding(optimized, size):
    """on a concrete message, the encoder evaluates keccak256 without any clause"""
    data = random.Random(size).randbytes(size)
    cnf = KeccakCNF(optimized)
    out = cnf.keccak256(bytes_to_bits(data))
    assert bits_to_bytes(out) == keccak(data)
    assert not cnf.clauses


def z3_solver(cnf: KeccakCNF) -> tuple[z3.Solver, list]:
    xs = [None] + [z3.Bool(f"v{i}") for i in range(1, cnf.num_vars + 1)]
    solver = z3.Solver()
    for clause in cnf.clauses:
        solver.add(z3.Or([xs[x] if x > 0 else z3.Not(xs[-x]) for x in clause]))
    return solver, xs


def z3_lit(xs, lit):
    if isinstance(lit, bool):
        return z3.BoolVal(lit)
    return xs[lit] if lit > 0 else z3.Not(xs[-lit])


def symbolic_message(cnf: KeccakCNF, data: bytes, free: list[int]) -> list:
    bits = bytes_to_bits(data)
    for pos in free:
        bits[pos] = cnf.new_input()
    return bits


@pytest.mark.parametrize("optimized", [True, False])
@pytest.mark.parametrize("size", [32, 150])
def test_cnf_preimage(optimized, size):
    """the only model of `keccak256(message) == digest` is the planted message"""
    rounds = 3
    data = random.Random(1).randbytes(size)
    free = [0, 1, 2, 9, 77, 130, 201, 255]
    cnf = KeccakCNF(optimized, rounds=rounds)
    message = symbolic_message(cnf, data, free)
    out = cnf.keccak256(message)

    solver, xs = z3_solver(cnf)
    digest = bytes_to_bits(keccak256(data, rounds=rounds))
    solver.add([z3_lit(xs, lit) == bit for lit, bit in zip(out, digest, strict=True)])
    assert solver.check() == z3.sat
    model = solver.model()
    for pos in free:
        assert (
            z3.is_true(model.eval(xs[message[pos]], True)) == bytes_to_bits(data)[pos]
        )

    # no other preimage
    solver.add(z3.Or([xs[message[pos]] != bytes_to_bits(data)[pos] for pos in free]))
    assert solver.check() == z3.unsat


def test_cnf_optimized_equals_textbook():
    """both encodings define the same function of the free bits (miter)"""
    rounds = 2
    data = random.Random(2).randbytes(64)
    free = list(range(248, 256))

    cnf = KeccakCNF(optimized=True, rounds=rounds)
    message = symbolic_message(cnf, data, free)
    out = cnf.keccak256(message)

    # the textbook encoding of the same message, in the same variable space
    textbook = KeccakCNF(optimized=False, rounds=rounds)
    textbook.num_vars = cnf.num_vars
    out2 = textbook.keccak256(message)
    textbook.clauses += cnf.clauses

    solver, xs = z3_solver(textbook)
    solver.add(
        z3.Or([z3_lit(xs, a) != z3_lit(xs, b) for a, b in zip(out, out2, strict=True)])
    )
    assert solver.check() == z3.unsat


def test_cofactor_cnf():
    """the table lookup defines keccak256 on the free bits"""
    data = random.Random(3).randbytes(64)
    free = [248, 250, 251, 255, 300]
    cnf = KeccakCNF()
    message = symbolic_message(cnf, data, free)
    out = cofactor_cnf(cnf, message, keccak)
    assert cnf.num_vars < 400

    positions, table = cofactor_table(message, keccak)
    assert positions == sorted(free) and len(table) == 32

    solver, xs = z3_solver(cnf)
    for u, digest in enumerate(table):
        value = [
            xs[message[pos]] == bool(u >> j & 1) for j, pos in enumerate(positions)
        ]
        # the digest is implied by the value of the free bits
        mismatch = z3.Or(
            [
                z3_lit(xs, lit) != bit
                for lit, bit in zip(out, bytes_to_bits(digest), strict=True)
            ]
        )
        assert solver.check(*value) == z3.sat
        assert solver.check(*value, mismatch) == z3.unsat


def test_cofactor_cnf_concrete():
    data = random.Random(4).randbytes(64)
    out = cofactor_cnf(KeccakCNF(), bytes_to_bits(data), keccak)
    assert bits_to_bytes(out) == keccak(data)


def test_dimacs_inputs_last():
    cnf = KeccakCNF(rounds=1)
    message = symbolic_message(cnf, bytes(32), [0, 1])
    cnf.keccak256(message)
    vmap = cnf.variable_map()
    assert sorted(vmap[v] for v in cnf.inputs) == [cnf.num_vars - 1, cnf.num_vars]
    header = cnf.dimacs([1]).splitlines()[0]
    assert header == f"p cnf {cnf.num_vars} {len(cnf.clauses) + 1}"


def test_free_bits():
    x8 = z3.BitVec("x8", 8)
    x256 = z3.BitVec("x256", 256)

    assert free_bits(z3.BitVecVal(42, 256)) == (0, 42)
    assert free_bits(z3.ZeroExt(248, x8)) == (0xFF, 0)
    assert free_bits(z3.Concat(z3.BitVecVal(0xAB, 8), x8)) == (0xFF, 0xAB00)
    assert free_bits(x256 & 0xF0) == (0xF0, 0)
    assert free_bits((x256 & 0x0F) | 0x30) == (0x0F, 0x30)
    assert free_bits(z3.Extract(15, 8, z3.Concat(x8, z3.BitVecVal(7, 8)))) == (0xFF, 0)
    assert free_bits(z3.ZeroExt(8, x8) << 4) == (0xFF0, 0)
    assert free_bits(z3.If(x8 == 0, z3.BitVecVal(5, 8), z3.BitVecVal(7, 8))) == (2, 5)
    assert free_bits(x256 + 1) == ((1 << 256) - 1, 0)
    assert free_bits(x8 == 0) is None


def test_free_bits_is_sound():
    """the constant bits reported by the analysis hold on random evaluations"""
    rnd = random.Random(5)
    x = z3.BitVec("x", 16)
    y = z3.BitVec("y", 16)
    terms = [
        z3.Concat(z3.Extract(7, 0, x & 0x3C), z3.BitVecVal(0x5A, 8))
        ^ z3.ZeroExt(12, z3.Extract(3, 0, y)),
        ~(z3.SignExt(8, z3.Extract(7, 0, x | 0x80)) & 0xFF0F),
        z3.LShR(z3.If(x == y, x & 0xFF00, y | 0x00FF), 3) | 0x8000,
        z3.SignExt(8, z3.Extract(7, 0, x & 0x7F)),
    ]
    for term in terms:
        mask, value = free_bits(term)
        assert mask != (1 << term.size()) - 1
        for _ in range(50):
            env = [
                (x, z3.BitVecVal(rnd.getrandbits(16), 16)),
                (y, z3.BitVecVal(rnd.getrandbits(16), 16)),
            ]
            result = z3.simplify(z3.substitute(term, *env)).as_long()
            assert result & ~mask == value


def test_exhaustive_keccak_values():
    x = z3.BitVec("x", 256)
    term = z3.Concat(z3.BitVecVal(1, 8), z3.Extract(7, 0, x) & 0x11)
    assert exhaustive_keccak_values(term, 8) == [0x100, 0x101, 0x110, 0x111]
    assert exhaustive_keccak_values(term, 1) is None
    assert exhaustive_keccak_values(x, 8) is None
    assert exhaustive_keccak_values(z3.BitVecVal(3, 8), 8) is None
