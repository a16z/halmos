# keccak256 and SAT solvers

Dolmos models keccak256 as uninterpreted functions `f_sha3_N`, checked after the
fact against the real hash (`--keccak-refinement-rounds`). This page documents the
bit-precise side: what a SAT solver can do with the real keccak256, the optimized
encoding of `dolmos.keccak_sat`, its equivalence proofs in Lean, and the option
`--keccak-exhaustive-bits`.

## What a solver can do with keccak256

A query on the full keccak256 (24 rounds) can only be decided by enumerating the
candidate preimages: the function is random-looking, no learned clause prunes more
than the candidate that produced it. With a bit-precise encoding, each candidate
costs a propagation of the whole circuit, about 90 000 variables and 25 to 50 ms in
the solvers tried (CaDiCaL, MiniSat, Glucose, Yices, Bitwuzla), against about 1 µs for
a native hash. This cost is close to a floor for a CNF: one round needs 3 200 two-input
xors (theta) and 1 600 chi gates, and after two rounds every state bit depends on
every free bit of the message, so nothing is shared between two candidates.

Two consequences:

- optimizing the circuit encoding gives a bounded gain, about 1.5x (measured below);
- the only large gain is to not propagate the circuit per candidate: when the message
  has `k` free bits with `k` small, the `2^k` digests are computed natively and the
  circuit is replaced by a case split (Shannon cofactoring on the free bits).

## Encodings (`src/dolmos/keccak_sat.py`)

`KeccakCNF(optimized=False)` is the textbook encoding: Tseitin encoding of the
two-input gates of the specification. `KeccakCNF()` differs by:

| optimization | effect |
| --- | --- |
| chi as one 4-variable gate (its 6 prime implicates) | no auxiliary variable, 6 clauses instead of 7 per bit |
| column parities as two 3-input xors | 2 variables instead of 4 per column bit |
| last round restricted to the digest | 4 chi lanes instead of 25, 5 theta lanes instead of 25 |
| free message bits numbered last | CDCL branches on the message: 256 conflicts instead of 1 258 at `k` = 8 |
| constant folding (padding, capacity, known bits) | both encodings |

`cofactor_cnf` replaces the circuit by the lookup of the free bits in the table of the
`2^k` digests, with one selector variable per entry and binary clauses.

## Equivalence proofs (`proofs/keccak_sat`)

Lean 4, no dependency (`lake build`, toolchain in `lean-toolchain`):

- `Spec.lean`: keccak-f[1600] as in FIPS 202, on 25 lanes of `BitVec 64`, checked on
  the digest of the empty message;
- `Templates.lean`: generated from the encoder (`python -m dolmos.keccak_sat
  lean-templates`, kept in sync by `tests/test_keccak_sat.py`). Each clause template
  holds iff its gate does, e.g. `chiCnf a b c o ↔ o = a ^^^ (~~~b &&& c)`, by
  `bv_decide`;
- `Encoding.lean`: `roundCnf_iff`, the clauses of a round hold iff the auxiliary
  variables and the output state are those of the specification;
  `squeezeCnf_sound`, any assignment satisfying the 23 full rounds and the truncated
  last round gives the digest lanes of `keccakF`; `squeezeCnf_complete`, the values of
  the specification satisfy the clauses for every input;
- `Cofactor.lean`: `cofactorCnf_iff`, the clauses of the table lookup hold iff
  `h = table x`; `cofactor_eq_circuit`, the lookup and the circuit give the same digest.

The proofs depend on `propext`, `Classical.choice`, `Quot.sound` and on the axioms of
`bv_decide` (SAT certificates checked by compiled code) for the three gate templates.

Not covered by the proofs: the encoder is modeled in bit-sliced form (one lane for 64
bit variables), and the numbering of the variables, the constant folding, the padding
and the absorption of several blocks are only tested (against `eth_hash`, and by SAT
miters between the two encodings on reduced rounds).

## Measurements

`benchmarks/keccak_sat.py`: 64-byte message with `k` free bits, digest fixed to the
one of a planted message (sat) or to an impossible one (unsat). One run on 2 vCPUs,
CaDiCaL 2.1.2, Yices 2.6.4, times include the encoding.

| query | SMT-LIB circuit, yices | CNF textbook | CNF optimized | CNF cofactor | SMT cases, yices |
| --- | --- | --- | --- | --- | --- |
| k = 8, unsat | 8.9 s | 12.6 s | 8.7 s | 0.14 s | 0.01 s |
| k = 8, sat (3 seeds) | 0.9 – 4.8 s | 2.7 – 11.8 s | 2.6 – 8.1 s | 0.12 s | 0.01 – 0.27 s |
| k = 12, unsat | 149 s | 163 s | 88 s | 2.3 s | 0.04 s |
| k = 12, sat | 100 s | 18.8 s | 15.7 s | 2.2 s | 0.33 s |
| k = 16, unsat | not run (~40 min extrapolated) | not run | not run | 44 s (17.9 M clauses) | 0.8 s |

"SMT cases" is the form used by dolmos (next section). The CNF table has `256 × 2^k`
binary clauses: 8.6 s at `k` = 14, out of memory (7 GB) at `k` = 20, where the SMT
form (a 160 MB query) also failed.

## `--keccak-exhaustive-bits K`

Disabled by default (`K` = 0). With `K` > 0, for each symbolic keccak256 whose
preimage has at most `K` free bits, the queries define the hash by cases:

```smt2
(assert (=> (= ((_ extract 7 0) sha3dom_0) (_ bv42 8)) (= sha3img_0 (_ bv<keccak256(42)> 256))))
```

The free bits are found syntactically (`keccak_sat.free_bits`: constants, `concat`,
extensions, `extract`, masks, shifts by constants, `ite`), which covers the cleanups
emitted by the compiler for small types: `keccak256(abi.encode(uint8 x))`,
`abi.encodePacked(bool, bytes2)`, a `mapping(uint8 => ...)` slot. A value restricted
only by a path condition (`vm.assume(x < 100)` on a `uint256`) is not detected.

On these hashes the queries are exact: a counterexample cannot rely on a wrong hash
value, and a property that depends on the value of the hash can be proved, instead
of failing with a counterexample reported as inconsistent with keccak256. At most
`2^16` cases are added to a query; `K` = 8 costs 256 cases per hash.
