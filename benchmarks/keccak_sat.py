#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0

"""
Benchmark of the bit-precise keccak256 encodings of dolmos.keccak_sat.

Query: a 64-byte message (a mapping slot preimage `key . slot`) whose k low bits of the key
are free, with a digest equal to the one of a planted key (sat), or to the same digest with
one bit flipped (unsat).

    python benchmarks/keccak_sat.py --sat-solver cadical --bits 8,12
    python benchmarks/keccak_sat.py --sat-solver cadical --smt-solver yices-smt2 --bits 8

Encodings:
  smt        lane-wise SMT-LIB definition of keccak256, bit-blasted by the SMT solver
  textbook   KeccakCNF(optimized=False): Tseitin encoding of the specification
  optimized  KeccakCNF(optimized=True): proved equivalent in proofs/keccak_sat
  cofactor   cofactor_cnf: table lookup on the free bits (Cofactor.lean)
  smt-cases  the queries of dolmos with --keccak-exhaustive-bits: the same cofactoring in
             SMT-LIB, on the uninterpreted hash (mk_keccak_facts of solve.py)
"""

import argparse
import os
import random
import re
import subprocess
import tempfile
import time

from dolmos.keccak_sat import (
    RC,
    ROT,
    KeccakCNF,
    bytes_to_bits,
    cofactor_cnf,
    keccak256,
    pi_src,
)

try:
    from eth_hash.auto import keccak as native_keccak
except ImportError:  # pragma: no cover
    native_keccak = keccak256


def free_positions(k: int) -> list[int]:
    """the k low bits of the first 32-byte big-endian word of the message"""
    return [8 * (31 - i // 8) + i % 8 for i in range(k)]


def cnf_query(
    encoding: str, k: int, sat: bool, seed: int
) -> tuple[KeccakCNF, list[int]]:
    msg = random.Random(seed).randbytes(64)
    cnf = KeccakCNF(optimized=encoding != "textbook")
    bits = bytes_to_bits(msg)
    for pos in free_positions(k):
        bits[pos] = cnf.new_input()
    if encoding == "cofactor":
        out = cofactor_cnf(cnf, bits, native_keccak)
    else:
        out = cnf.keccak256(bits)

    digest = bytes_to_bits(keccak256(msg))
    if not sat:
        digest[7] = not digest[7]
    units = []
    for lit, bit in zip(out, digest, strict=True):
        if isinstance(lit, bool):
            if lit != bit:  # trivially unsat
                var = cnf.new_var()
                units += [var, -var]
            continue
        units.append(lit if bit else -lit)
    return cnf, units


def _bswap(term: str) -> str:
    return (
        "(concat "
        + " ".join(f"((_ extract {8 * i + 7} {8 * i}) {term})" for i in range(8))
        + ")"
    )


def smt_keccak_def(nbytes: int) -> str:
    """lane-wise SMT-LIB definition of keccak256 on nbytes-byte messages (single block)"""
    assert nbytes < 136
    pad = bytearray(136 - nbytes)
    pad[0] |= 0x01
    pad[-1] |= 0x80
    lines = [f"(define-fun keccak ((m (_ BitVec {8 * nbytes}))) (_ BitVec 256)"]
    lines.append(f" (let ((blk (concat m #x{pad.hex()})))")
    lanes = [
        _bswap(f"((_ extract {1087 - 64 * i} {1024 - 64 * i}) blk)") if i < 17 else "#x0000000000000000"
        for i in range(25)
    ]  # fmt: skip
    lines.append(
        " (let (" + " ".join(f"(a0_{i} {lane})" for i, lane in enumerate(lanes)) + ")"
    )
    for r in range(24):
        lines.append(" (let (" + " ".join(
            f"(c{r}_{x} (bvxor a{r}_{x} a{r}_{x+5} a{r}_{x+10} a{r}_{x+15} a{r}_{x+20}))" for x in range(5)) + ")")  # fmt: skip
        lines.append(" (let (" + " ".join(
            f"(d{r}_{x} (bvxor c{r}_{(x+4)%5} ((_ rotate_left 1) c{r}_{(x+1)%5})))" for x in range(5)) + ")")  # fmt: skip
        lines.append(" (let (" + " ".join(
            f"(b{r}_{i} ((_ rotate_left {ROT[pi_src(i)]}) (bvxor a{r}_{pi_src(i)} d{r}_{pi_src(i) % 5})))"
            for i in range(25)) + ")")  # fmt: skip
        outs = []
        for i in range(25):
            x, y = i % 5, i // 5
            term = f"(bvxor b{r}_{i} (bvand (bvnot b{r}_{(x + 1) % 5 + 5 * y}) b{r}_{(x + 2) % 5 + 5 * y}))"
            if i == 0:
                term = f"(bvxor {term} #x{RC[r]:016x})"
            outs.append(f"(a{r + 1}_{i} {term})")
        lines.append(" (let (" + " ".join(outs) + ")")
    lines.append(" (concat " + " ".join(_bswap(f"a24_{i}") for i in range(4)) + ")")
    lines.append(")" * (2 + 4 * 24 + 1))
    return "\n".join(lines) + "\n"


def smt_query(k: int, sat: bool, seed: int) -> str:
    msg = random.Random(seed).randbytes(64)
    digest = int.from_bytes(keccak256(msg), "big")
    if not sat:
        digest ^= 1 << 255
    m = int.from_bytes(msg, "big")
    hi, lo = m >> (256 + k), m & ((1 << 256) - 1)
    return (
        "(set-logic QF_BV)\n"
        + smt_keccak_def(64)
        + f"(declare-const x (_ BitVec {k}))\n"
        + f"(assert (= (keccak (concat (_ bv{hi} {256 - k}) x (_ bv{lo} 256))) (_ bv{digest} 256)))\n"
        + "(check-sat)\n"
    )


def smt_cases_query(k: int, sat: bool, seed: int) -> str:
    """the query of dolmos with --keccak-exhaustive-bits: uninterpreted hash, defined by cases"""
    import z3

    from dolmos.solve import mk_keccak_facts

    msg = random.Random(seed).randbytes(64)
    digest = int.from_bytes(keccak256(msg), "big")
    if not sat:
        digest ^= 1 << 255
    m = int.from_bytes(msg, "big")
    hi, lo = m >> (256 + k), m & ((1 << 256) - 1)
    data = z3.Concat(
        z3.BitVecVal(hi, 256 - k), z3.BitVec("x", k), z3.BitVecVal(lo, 256)
    )
    f_sha3 = z3.Function("f_sha3_512", z3.BitVecSort(512), z3.BitVecSort(256))
    return (
        "(set-logic QF_AUFBV)\n"
        "(declare-fun f_sha3_512 ((_ BitVec 512)) (_ BitVec 256))\n"
        f"(declare-const x (_ BitVec {k}))\n"
        f"(assert (= (f_sha3_512 {data.sexpr()}) (_ bv{digest} 256)))\n"
        + mk_keccak_facts([f_sha3(data)], k)
        + "(check-sat)\n"
    )


def run(
    cmd: list[str], text: str, suffix: str, timeout: float
) -> tuple[float | None, str]:
    with tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False) as f:
        f.write(text)
    try:
        start = time.perf_counter()
        proc = subprocess.run(
            [*cmd, f.name], capture_output=True, text=True, timeout=timeout
        )
        return time.perf_counter() - start, proc.stdout
    except subprocess.TimeoutExpired:
        return None, ""
    finally:
        os.unlink(f.name)


def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument(
        "--sat-solver", help="DIMACS solver command, e.g. cadical or kissat"
    )
    parser.add_argument(
        "--smt-solver",
        action="append",
        default=[],
        help="SMT-LIB solver command (repeatable)",
    )
    parser.add_argument(
        "--bits", default="8", help="comma separated numbers of free bits"
    )
    parser.add_argument("--seeds", type=int, default=2)
    parser.add_argument("--timeout", type=float, default=600)
    parser.add_argument(
        "--max-circuit-bits",
        type=int,
        default=12,
        help="skip the circuit encodings above this number of free bits",
    )
    parser.add_argument("--encodings", default="textbook,optimized,cofactor")
    args = parser.parse_args()

    for k in map(int, args.bits.split(",")):
        for sat in (True, False):
            kind = "sat  " if sat else "unsat"
            for solver in args.smt_solver:
                name = os.path.basename(solver.split()[0])
                for label, mk_query in (
                    ("smt", smt_query),
                    ("smt-cases", smt_cases_query),
                ):
                    if label == "smt" and k > args.max_circuit_bits:
                        continue
                    times = []
                    for seed in range(args.seeds):
                        start = time.perf_counter()
                        text = mk_query(k, sat, seed)
                        encode = time.perf_counter() - start
                        elapsed, stdout = run(
                            solver.split(), text, ".smt2", args.timeout
                        )
                        expected = "sat" if sat else "unsat"
                        if elapsed is not None and stdout.split()[:1] != [expected]:
                            raise RuntimeError(
                                f"{name}: unexpected result {stdout[:80]!r}"
                            )
                        times.append(None if elapsed is None else elapsed + encode)
                    shown = ", ".join(
                        "timeout" if t is None else f"{t:.2f}s" for t in times
                    )
                    print(
                        f"k={k:2d} {kind} {label + '/' + name:24s} {'':30s} {shown}",
                        flush=True,
                    )
            if not args.sat_solver:
                continue
            for encoding in args.encodings.split(","):
                if encoding != "cofactor" and k > args.max_circuit_bits:
                    continue
                times, sizes, conflicts = [], "", []
                for seed in range(args.seeds):
                    start = time.perf_counter()
                    cnf, units = cnf_query(encoding, k, sat, seed)
                    text = cnf.dimacs(units)
                    encode = time.perf_counter() - start
                    sizes = f"vars={cnf.num_vars:7d} clauses={len(cnf.clauses):8d}"
                    elapsed, stdout = run(
                        args.sat_solver.split(), text, ".cnf", args.timeout
                    )
                    times.append(None if elapsed is None else elapsed + encode)
                    if m := re.search(r"conflicts:\s+(\d+)", stdout):
                        conflicts.append(int(m.group(1)))
                shown = ", ".join(
                    "timeout" if t is None else f"{t:.2f}s" for t in times
                )
                print(
                    f"k={k:2d} {kind} {'cnf/' + encoding:24s} {sizes} {shown}  conflicts={conflicts}",
                    flush=True,
                )


if __name__ == "__main__":
    main()
