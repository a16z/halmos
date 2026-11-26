# SPDX-License-Identifier: AGPL-3.0

"""
Bit-precise keccak256 for SAT solvers.

Dolmos models keccak256 as uninterpreted functions (see Exec.sha3_data and the keccak
refinement of solve.py). This module provides the bit-precise side:

- a reference implementation of keccak-f[1600] and keccak256 (`keccak_f`, `keccak256`);

- `KeccakCNF`, a CNF encoder of keccak256 for messages whose bits are literals or constants.
  The optimized encoding (the default) differs from the textbook Tseitin encoding by:
    * chi encoded as a single 4-variable gate (6 clauses, no auxiliary variable),
    * column parities encoded with two 3-input xors instead of four 2-input xors,
    * a last round restricted to the 256 output bits (4 chi lanes, 5 theta lanes),
    * constants (padding, capacity, known message bits) folded at encoding time,
    * free message bits numbered last, so that CDCL solvers branch on them first.
  The clause templates and the round structure are proved equivalent to the keccak-f
  specification in Lean, see proofs/keccak_sat (`python -m dolmos.keccak_sat lean-templates`
  regenerates the Lean templates from the ones used here);

- `cofactor_cnf` / `cofactor_table`: Shannon cofactoring of keccak256 on the free bits of
  the message. A full keccak256 is a random-looking function: a SAT solver can only decide
  a query on it by enumerating the candidate preimages, and each candidate costs a full
  propagation of the circuit (~90k variables, ~25 ms). When the message has k free bits,
  with k small, the 2^k digests are instead computed natively and the circuit is replaced
  by a table lookup, which is equivalent (see Cofactor.lean) and orders of magnitude faster;

- `free_bits` / `exhaustive_keccak_values`: the same idea for the SMT queries of dolmos, as
  facts `f_sha3_N(v) == keccak256(v)` for all the values v of a preimage with few free bits
  (--keccak-exhaustive-bits).
"""

from collections.abc import Iterable, Sequence

MASK64 = (1 << 64) - 1

# round constants of iota
RC = (
    0x0000000000000001, 0x0000000000008082, 0x800000000000808A, 0x8000000080008000,
    0x000000000000808B, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
    0x000000000000008A, 0x0000000000000088, 0x0000000080008009, 0x000000008000000A,
    0x000000008000808B, 0x800000000000008B, 0x8000000000008089, 0x8000000000008003,
    0x8000000000008002, 0x8000000000000080, 0x000000000000800A, 0x800000008000000A,
    0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
)  # fmt: skip

# rotation offsets of rho, indexed by x + 5*y
ROT = (
    0, 1, 62, 28, 27,
    36, 44, 6, 55, 20,
    3, 10, 43, 25, 39,
    41, 45, 15, 21, 8,
    18, 2, 61, 56, 14,
)  # fmt: skip

RATE_BITS = 1088  # keccak256: rate of 136 bytes, capacity of 512 bits


#
# reference implementation
#


def _rol(v: int, n: int) -> int:
    return ((v << n) | (v >> (64 - n))) & MASK64 if n else v


def pi_src(i: int) -> int:
    """index of the lane moved to index i by pi: (x, y) = (X + 3Y, X)"""
    x, y = i % 5, i // 5
    return (x + 3 * y) % 5 + 5 * x


def keccak_f(lanes: Sequence[int], rounds: int = 24) -> list[int]:
    """keccak-f[1600] on 25 lanes (lane (x, y) at index x + 5*y)"""
    a = list(lanes)
    for r in range(rounds):
        c = [a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] for x in range(5)]
        d = [c[(x + 4) % 5] ^ _rol(c[(x + 1) % 5], 1) for x in range(5)]
        t = [a[i] ^ d[i % 5] for i in range(25)]
        b = [_rol(t[pi_src(i)], ROT[pi_src(i)]) for i in range(25)]
        a = [
            b[i] ^ (~b[(i % 5 + 1) % 5 + 5 * (i // 5)] & b[(i % 5 + 2) % 5 + 5 * (i // 5)] & MASK64)
            for i in range(25)
        ]  # fmt: skip
        a[0] ^= RC[r]
    return a


def keccak256(data: bytes, rounds: int = 24) -> bytes:
    """reference keccak256 (the function of the SHA3 opcode, not NIST SHA3-256)"""
    padded = bytearray(data)
    padded.append(0x01)
    while len(padded) % 136:
        padded.append(0)
    padded[-1] |= 0x80

    a = [0] * 25
    for offset in range(0, len(padded), 136):
        for i in range(17):
            a[i] ^= int.from_bytes(
                padded[offset + 8 * i : offset + 8 * i + 8], "little"
            )
        a = keccak_f(a, rounds)
    return b"".join(lane.to_bytes(8, "little") for lane in a[:4])


#
# clause templates
#
# A template is the CNF of a gate, over the variables 1..n (inputs) and n+1 (output).
# They are mirrored in proofs/keccak_sat/KeccakSat/Templates.lean, where each of them is
# proved equivalent to its gate.
#

Clause = tuple[int, ...]

# o <-> a ^ b
XOR2_CNF: tuple[Clause, ...] = ((1, 2, -3), (-1, -2, -3), (-1, 2, 3), (1, -2, 3))

# o <-> a ^ b ^ c
XOR3_CNF: tuple[Clause, ...] = (
    (1, 2, 3, -4), (-1, -2, 3, -4), (-1, 2, -3, -4), (1, -2, -3, -4),
    (-1, 2, 3, 4), (1, -2, 3, 4), (1, 2, -3, 4), (-1, -2, -3, 4),
)  # fmt: skip

# o <-> a & b
AND_CNF: tuple[Clause, ...] = ((1, -3), (2, -3), (-1, -2, 3))

# o <-> a ^ (~b & c): the prime implicates of the chi gate, no auxiliary variable
CHI_CNF: tuple[Clause, ...] = (
    (1, 3, -4), (-1, 3, 4), (1, -2, -4), (-1, -2, 4),
    (1, 2, -3, 4), (-1, 2, -3, -4),
)  # fmt: skip

TEMPLATES = {
    "xor2": (XOR2_CNF, "a ^^^ b"),
    "xor3": (XOR3_CNF, "a ^^^ b ^^^ c"),
    "and": (AND_CNF, "a &&& b"),
    "chi": (CHI_CNF, "a ^^^ (~~~b &&& c)"),
}


def template_holds(cnf: Iterable[Clause], values: Sequence[bool]) -> bool:
    """evaluates a template under the given values of the variables 1..len(values)"""
    return all(
        any(values[abs(lit) - 1] == (lit > 0) for lit in clause) for clause in cnf
    )


def lean_templates() -> str:
    """
    The Lean source of the templates, in bit-sliced form: a clause over lanes holds when it
    holds at each of the 64 bit positions, i.e. when the disjunction of its literals is -1.
    """
    names = "abcdefg"
    out = [
        "/-",
        "  Clause templates of the CNF encoder (src/dolmos/keccak_sat.py).",
        "",
        "  GENERATED by `python -m dolmos.keccak_sat lean-templates`, do not edit:",
        "  tests/test_keccak_sat.py checks that this file is in sync with the encoder.",
        "",
        "  A clause over lanes is bit-sliced: `l1 ||| l2 ||| l3 = -1` states that the clause",
        "  `l1[i] ∨ l2[i] ∨ l3[i]` holds at each bit position i (see `clause_iff_bits`).",
        "-/",
        "import Std.Tactic.BVDecide",
        "",
        "namespace KeccakSat",
        "",
        "/-- a bit-sliced clause holds iff it holds at each of the 64 bit positions -/",
        "theorem clause_iff_bits (c : BitVec 64) : c = -1#64 ↔ ∀ i : Fin 64, c[i] = true := by",
        "  have ones : ∀ i : Fin 64, (-1#64)[i] = true := by decide",
        "  constructor",
        "  · intro h i; subst h; exact ones i",
        "  · intro h; apply BitVec.eq_of_getElem_eq; intro i hi",
        "    exact (h ⟨i, hi⟩).trans (ones ⟨i, hi⟩).symm",
        "",
    ]
    for name, (cnf, gate) in TEMPLATES.items():
        n = max(abs(lit) for clause in cnf for lit in clause)
        vs = [*names[: n - 1], "o"]
        params = " ".join(vs)

        def lit(literal: int, vs=vs) -> str:
            return vs[literal - 1] if literal > 0 else f"~~~{vs[-literal - 1]}"

        clauses = [" ||| ".join(lit(x) for x in clause) + " = -1#64" for clause in cnf]
        out.append(f"/-- the {len(cnf)} clauses of the gate `o = {gate}` -/")
        out.append(f"def {name}Cnf ({params} : BitVec 64) : Prop :=")
        out.append("  " + " ∧\n  ".join(f"({c})" for c in clauses))
        out.append("")
        out.append(
            f"theorem {name}Cnf_iff ({params} : BitVec 64) : {name}Cnf {params} ↔ o = {gate} := by"
        )
        out.append(f"  unfold {name}Cnf; bv_decide")
        out.append("")
    out.append("end KeccakSat")
    return "\n".join(out) + "\n"


#
# CNF encoder
#

# a literal is a non-zero int (DIMACS convention), a constant is a bool
Lit = int | bool


def bytes_to_bits(data: bytes) -> list[bool]:
    """bit j (lsb first) of byte i at index 8*i + j: the order of the keccak state"""
    return [bool(data[i // 8] >> (i % 8) & 1) for i in range(8 * len(data))]


def bits_to_bytes(bits: Sequence[bool]) -> bytes:
    return bytes(
        sum(int(bits[8 * i + j]) << j for j in range(8)) for i in range(len(bits) // 8)
    )


class KeccakCNF:
    """
    CNF encoder of keccak256.

    optimized=False gives the textbook encoding, used as the baseline of the benchmark:
    Tseitin encoding of the 2-input gates of the specification, all the rounds in full.
    Constants are folded in both cases.
    """

    def __init__(self, optimized: bool = True, rounds: int = 24) -> None:
        self.optimized = optimized
        self.rounds = rounds
        self.num_vars = 0
        self.clauses: list[list[int]] = []
        self.inputs: list[int] = []
        self._xors: dict[tuple[int, ...], Lit] = {}
        self._ands: dict[tuple[int, int], int] = {}
        self._chis: dict[tuple[int, int, int], int] = {}

    def new_var(self) -> int:
        self.num_vars += 1
        return self.num_vars

    def new_input(self) -> int:
        """a free message bit"""
        var = self.new_var()
        self.inputs.append(var)
        return var

    def add_clause(self, clause: Iterable[int]) -> None:
        self.clauses.append(list(clause))

    def _instantiate(self, template: Iterable[Clause], lits: Sequence[int]) -> None:
        for clause in template:
            self.add_clause(lits[abs(x) - 1] * (1 if x > 0 else -1) for x in clause)

    @staticmethod
    def neg(lit: Lit) -> Lit:
        return (not lit) if isinstance(lit, bool) else -lit

    def xor(self, lits: Iterable[Lit], arity: int = 2) -> Lit:
        """xor of the given literals, as gates of at most `arity` inputs"""
        parity = False
        odd: dict[int, bool] = {}
        for lit in lits:
            if isinstance(lit, bool):
                parity ^= lit
                continue
            if lit < 0:
                parity = not parity
                lit = -lit
            odd[lit] = not odd.get(lit, False)
        # the gates are grouped in the order of the arguments (as in Encoding.lean)
        variables = [v for v, is_odd in odd.items() if is_odd]
        key = tuple(sorted(variables))

        if not variables:
            return parity
        if len(variables) == 1:
            out = variables[0]
        elif (out := self._xors.get(key)) is None:
            if len(variables) == 2:
                out = self.new_var()
                self._instantiate(XOR2_CNF, [*variables, out])
            elif len(variables) == 3 and arity >= 3:
                out = self.new_var()
                self._instantiate(XOR3_CNF, [*variables, out])
            else:
                # may fold further, if the head is one of the remaining variables
                head = self.xor(variables[:arity], arity)
                out = self.xor([head, *variables[arity:]], arity)
            self._xors[key] = out
        if isinstance(out, bool):
            return out != parity
        return -out if parity else out

    def and_(self, a: Lit, b: Lit) -> Lit:
        if a is False or b is False:
            return False
        if a is True:
            return b
        if b is True:
            return a
        if a == b:
            return a
        if a == -b:
            return False
        key = (min(a, b), max(a, b))
        if (out := self._ands.get(key)) is None:
            out = self.new_var()
            self._instantiate(AND_CNF, [a, b, out])
            self._ands[key] = out
        return out

    def chi(self, a: Lit, b: Lit, c: Lit) -> Lit:
        """a ^ (~b & c)"""
        direct = (
            self.optimized
            and not any(isinstance(lit, bool) for lit in (a, b, c))
            and len({abs(a), abs(b), abs(c)}) == 3
        )
        if not direct:
            return self.xor([a, self.and_(self.neg(b), c)])
        key = (a, b, c)
        if (out := self._chis.get(key)) is None:
            out = self.new_var()
            self._instantiate(CHI_CNF, [a, b, c, out])
            self._chis[key] = out
        return out

    def permute(
        self, state: Sequence[Sequence[Lit]], squeeze: bool = True
    ) -> list[list[Lit]]:
        """
        keccak-f[1600] on 25 lanes of 64 literals (bit z at index z).

        With the optimized encoding and squeeze=True, the last round only computes the
        lanes 0..3 (the keccak256 digest); the other lanes of the result are None.
        """
        a = [list(lane) for lane in state]
        column_arity = 3 if self.optimized else 2
        for r in range(self.rounds):
            last = self.optimized and squeeze and r == self.rounds - 1
            c = [
                [self.xor([a[x + 5 * y][z] for y in range(5)], column_arity) for z in range(64)]
                for x in range(5)
            ]  # fmt: skip
            d = [
                [self.xor([c[(x + 4) % 5][z], c[(x + 1) % 5][(z - 1) % 64]]) for z in range(64)]
                for x in range(5)
            ]  # fmt: skip

            # in the last round, only the row y = 0 of the chi inputs is needed
            needed = {pi_src(i) for i in range(5)} if last else set(range(25))
            t = [
                [self.xor([a[i][z], d[i % 5][z]]) for z in range(64)] if i in needed else None
                for i in range(25)
            ]  # fmt: skip

            def b(i: int, z: int, t=t) -> Lit:
                src = pi_src(i)
                return t[src][(z - ROT[src]) % 64]

            a = []
            for i in range(25):
                if last and i >= 4:
                    a.append(None)
                    continue
                x, y = i % 5, i // 5
                i1, i2 = (x + 1) % 5 + 5 * y, (x + 2) % 5 + 5 * y
                lane = [self.chi(b(i, z), b(i1, z), b(i2, z)) for z in range(64)]
                if i == 0:  # iota
                    lane = [
                        self.neg(lit) if RC[r] >> z & 1 else lit
                        for z, lit in enumerate(lane)
                    ]
                a.append(lane)
        return a

    def keccak256(self, message: Sequence[Lit]) -> list[Lit]:
        """
        Digest of a message given as literals and constants (see bytes_to_bits for the
        bit order, which is also the one of the 256 returned bits).
        """
        nbits = len(message)
        assert nbits % 8 == 0

        state: list[list[Lit]] = [[False] * 64 for _ in range(25)]
        padded = list(message) + [True] + [False] * ((-nbits - 2) % RATE_BITS) + [True]
        if nbits % RATE_BITS == RATE_BITS - 8:  # a single padding byte 0x81
            padded = list(message) + [True] + [False] * 6 + [True]
        assert len(padded) % RATE_BITS == 0

        nblocks = len(padded) // RATE_BITS
        for n in range(nblocks):
            block = padded[n * RATE_BITS : (n + 1) * RATE_BITS]
            for i in range(17):
                state[i] = [
                    self.xor([state[i][z], block[64 * i + z]]) for z in range(64)
                ]
            state = self.permute(state, squeeze=n == nblocks - 1)
        return [lit for lane in state[:4] for lit in lane]

    def variable_map(self, inputs_last: bool | None = None) -> list[int]:
        """
        The renumbering applied by dimacs(): by default, the optimized encoding numbers
        the variables in reverse order, hence the free message bits last. CDCL solvers
        then branch on the message bits first (2^k conflicts for k free bits), instead of
        guessing internal state bits.
        """
        if inputs_last is None:
            inputs_last = self.optimized
        n = self.num_vars
        if inputs_last:
            return [0] + [n + 1 - v for v in range(1, n + 1)]
        return list(range(n + 1))

    def dimacs(
        self, assumptions: Iterable[int] = (), inputs_last: bool | None = None
    ) -> str:
        """DIMACS of the encoding, with the given literals asserted as unit clauses"""
        vmap = self.variable_map(inputs_last)
        clauses = self.clauses + [[lit] for lit in assumptions]
        lines = [f"p cnf {self.num_vars} {len(clauses)}"]
        lines.extend(
            " ".join(str(vmap[x] if x > 0 else -vmap[-x]) for x in clause) + " 0"
            for clause in clauses
        )
        return "\n".join(lines) + "\n"


#
# cofactoring on the free bits of the message
#


def cofactor_table(
    message: Sequence[Lit | None], hash_fn=keccak256
) -> tuple[list[int], list[bytes]]:
    """
    Digests of all the instances of a message with free bits (None, or a literal).

    Returns the positions of the free bits, and the table of the 2^k digests: entry u is the
    digest of the message whose j-th free bit is bit j of u.
    """
    free = [i for i, bit in enumerate(message) if not isinstance(bit, bool)]
    base = bytearray(bits_to_bytes([bit is True for bit in message]))
    table = []
    for u in range(1 << len(free)):
        data = bytearray(base)
        for j, pos in enumerate(free):
            if u >> j & 1:
                data[pos // 8] |= 1 << (pos % 8)
        table.append(hash_fn(bytes(data)))
    return free, table


def cofactor_cnf(
    cnf: KeccakCNF, message: Sequence[Lit], hash_fn=keccak256
) -> list[Lit]:
    """
    Same contract as KeccakCNF.keccak256, by Shannon cofactoring on the free bits: the
    2^k digests are computed natively, and the circuit is replaced by a table lookup.

    With one selector variable s_u per entry u of the table:
      s_u -> x_j = u_j         for each free bit j         (binary clauses)
      (x = u) -> s_u                                        (one clause of k+1 literals)
      s_u -> h_b = table[u]_b  for each non constant digest bit b  (binary clauses)
    See Cofactor.lean for the proof that these clauses hold iff h = table[x].
    """
    free, table = cofactor_table(message, hash_fn)
    k = len(free)
    digests = [bytes_to_bits(h) for h in table]
    if k == 0:
        return list(digests[0])

    # digest bits that are the same for all the entries are constants
    out: list[Lit] = []
    for b in range(256):
        column = {digest[b] for digest in digests}
        out.append(column.pop() if len(column) == 1 else cnf.new_var())

    xs = [message[pos] for pos in free]
    for u, digest in enumerate(digests):
        value = [x if u >> j & 1 else -x for j, x in enumerate(xs)]
        sel = cnf.new_var()
        for lit in value:
            cnf.add_clause([-sel, lit])
        cnf.add_clause([sel, *(-lit for lit in value)])
        for b, h in enumerate(out):
            if not isinstance(h, bool):
                cnf.add_clause([-sel, h if digest[b] else -h])
    return out


#
# small preimage domains in the SMT queries of dolmos
#


def free_bits(term) -> tuple[int, int] | None:
    """
    Known bits analysis of a z3 bitvector term: returns (mask, value), where mask has a 1
    for each bit of the term that may vary, and value gives the other bits. Returns None
    for non-bitvector terms. The analysis is conservative: a bit that is not proved
    constant is reported as free.
    """
    import z3

    if not z3.is_bv(term):
        return None
    return _free_bits(term, {})


def _free_bits(term, cache: dict) -> tuple[int, int]:
    import z3

    key = term.get_id()
    if (result := cache.get(key)) is not None:
        return result

    size = term.size()
    full = (1 << size) - 1
    kind = term.decl().kind()
    args = term.children()
    result = (full, 0)

    if z3.is_bv_value(term):
        result = (0, term.as_long())

    elif kind == z3.Z3_OP_CONCAT:
        mask = value = 0
        for arg in args:
            m, v = _free_bits(arg, cache)
            mask = (mask << arg.size()) | m
            value = (value << arg.size()) | v
        result = (mask, value)

    elif kind == z3.Z3_OP_ZERO_EXT:
        result = _free_bits(args[0], cache)

    elif kind == z3.Z3_OP_SIGN_EXT:
        m, v = _free_bits(args[0], cache)
        n = args[0].size()
        ext = ((1 << (size - n)) - 1) << n
        if m >> (n - 1) & 1:
            result = (m | ext, v)
        else:
            result = (m, v | ext if v >> (n - 1) & 1 else v)

    elif kind == z3.Z3_OP_EXTRACT:
        hi, lo = term.params()
        m, v = _free_bits(args[0], cache)
        width = (1 << (hi - lo + 1)) - 1
        result = ((m >> lo) & width, (v >> lo) & width)

    elif kind in (z3.Z3_OP_BAND, z3.Z3_OP_BOR):
        # known0/known1: bits proved to be 0/1
        is_and = kind == z3.Z3_OP_BAND
        known0, known1 = (0, full) if is_and else (full, 0)
        for arg in args:
            m, v = _free_bits(arg, cache)
            k0, k1 = ~m & ~v & full, ~m & v
            if is_and:
                known0, known1 = known0 | k0, known1 & k1
            else:
                known0, known1 = known0 & k0, known1 | k1
        result = (~(known0 | known1) & full, known1)

    elif kind == z3.Z3_OP_BXOR:
        mask = value = 0
        for arg in args:
            m, v = _free_bits(arg, cache)
            mask, value = mask | m, value ^ v
        result = (mask, value & ~mask)

    elif kind == z3.Z3_OP_BNOT:
        m, v = _free_bits(args[0], cache)
        result = (m, ~v & ~m & full)

    elif kind in (z3.Z3_OP_BSHL, z3.Z3_OP_BLSHR) and z3.is_bv_value(args[1]):
        m, v = _free_bits(args[0], cache)
        n = args[1].as_long()
        if n >= size:
            result = (0, 0)
        elif kind == z3.Z3_OP_BSHL:
            result = ((m << n) & full, (v << n) & full)
        else:
            result = (m >> n, v >> n)

    elif kind == z3.Z3_OP_ITE:
        m1, v1 = _free_bits(args[1], cache)
        m2, v2 = _free_bits(args[2], cache)
        mask = m1 | m2 | (v1 ^ v2)
        result = (mask, v1 & ~mask)

    cache[key] = result
    return result


def exhaustive_keccak_values(term, max_bits: int) -> list[int] | None:
    """
    All the values that the given z3 term can take, if it has at most max_bits free bits
    (and at least one); None otherwise. A superset of the values of the term under any
    path condition, hence a complete case split of keccak256 on this preimage.
    """
    result = free_bits(term)
    if result is None:
        return None
    mask, value = result
    k = mask.bit_count()
    if k == 0 or k > max_bits:
        return None

    positions = [i for i in range(term.size()) if mask >> i & 1]
    values = []
    for u in range(1 << k):
        v = value
        for j, pos in enumerate(positions):
            if u >> j & 1:
                v |= 1 << pos
        values.append(v)
    return values


if __name__ == "__main__":
    import sys

    if sys.argv[1:] == ["lean-templates"]:
        # utf8 with LF line endings, whatever the platform (the file is compared byte for
        # byte by the tests, and the encoding of stdout is cp1252 on Windows)
        sys.stdout.buffer.write(lean_templates().encode("utf8"))
    else:
        sys.exit("usage: python -m dolmos.keccak_sat lean-templates")
