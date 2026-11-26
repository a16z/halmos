# SPDX-License-Identifier: AGPL-3.0

"""
Export of bounded loops as lasso programs, for termination analysis with PaSTTeL.

When the loop unrolling bound (--loop) is reached on a symbolic JUMPI, dolmos can
export the loop as a *lasso*: a stem (how the execution reaches the loop) and a
loop transition (one iteration of the body), in PaSTTeL's JSON format
(https://github.com/Dowsers/PaSTTeL).

Extraction (see SEVM.extract_lasso)
- the loop variables are the stack slots that change between two visits
- the lasso is cut right after the JUMPI, on the branch that stays in the loop
- the body is re-executed once from a generalized state (fresh loop variables),
  on a separate solver; each path that comes back and takes the loop branch
  again is a disjunct of the loop transition

Translation (Translator): bitvectors become non-negative integers. Exact where
possible, over-approximated otherwise (fresh variables), so that termination
proofs stay valid.

By default, lassos use the *small-constants encoding*: no literal exceeds 2^52,
because PaSTTeL computes with doubles and is unsound on 2^256 constants.
Wrap-arounds are proven absent with z3 (bitvector semantics) when possible, and
over-approximated without large constants otherwise.

See docs/loop-termination.md for details, soundness and limitations.
"""

import json
import os
import re
import subprocess
from dataclasses import dataclass, field

from z3 import (
    UGE,
    ULT,
    Z3_OP_AND,
    Z3_OP_BADD,
    Z3_OP_BAND,
    Z3_OP_BLSHR,
    Z3_OP_BMUL,
    Z3_OP_BNEG,
    Z3_OP_BNUM,
    Z3_OP_BSHL,
    Z3_OP_BSUB,
    Z3_OP_BUDIV,
    Z3_OP_BUDIV_I,
    Z3_OP_BUREM,
    Z3_OP_BUREM_I,
    Z3_OP_CONCAT,
    Z3_OP_DISTINCT,
    Z3_OP_EQ,
    Z3_OP_EXTRACT,
    Z3_OP_FALSE,
    Z3_OP_IFF,
    Z3_OP_IMPLIES,
    Z3_OP_ITE,
    Z3_OP_NOT,
    Z3_OP_OR,
    Z3_OP_SGEQ,
    Z3_OP_SGT,
    Z3_OP_SLEQ,
    Z3_OP_SLT,
    Z3_OP_TRUE,
    Z3_OP_UGEQ,
    Z3_OP_UGT,
    Z3_OP_ULEQ,
    Z3_OP_ULT,
    Z3_OP_UNINTERPRETED,
    Z3_OP_XOR,
    Z3_OP_ZERO_EXT,
    And,
    BitVec,
    BitVecRef,
    BitVecVal,
    BoolRef,
    ExprRef,
    LShR,
    Not,
    Or,
    Solver,
    Sum,
    ZeroExt,
    is_bool,
    is_bv,
    is_bv_value,
    is_false,
    is_true,
    simplify,
    substitute,
    unsat,
)
from z3.z3util import get_vars

# upper bound on the paths of the generalized iteration
MAX_BODY_PATHS = 32

# upper bound on the number of instructions executed by the generalized iteration
MAX_BODY_STEPS = 200_000

LOOP_VAR_PREFIX = "lasso_v"

# wrap-arounds with at most this many cases are encoded as disjunctions
MAX_WRAP_CASES = 4

# PaSTTeL stores numbers as doubles: integers are exact up to 2^53
MAX_SMALL_CONSTANT = 2**52


#
# snapshots and results
#


@dataclass(frozen=True)
class LoopSnapshot:
    stack: tuple  # stack below the JUMPI operands
    cond: BoolRef  # branching condition


@dataclass
class LassoResult:
    test: str
    jumpid: str
    direction: bool
    path: str | None = None  # dumped JSON file
    error: str | None = None  # extraction failure
    warnings: list[str] = field(default_factory=list)
    verdict: str | None = None  # PaSTTeL verdict
    proof: str | None = None
    approximate: bool = False  # the lasso over-approximates the loop

    def summary(self) -> str:
        where = f"loop {self.jumpid} ({'true' if self.direction else 'false'} branch)"
        if self.error:
            return f"{where}: lasso not extracted: {self.error}"
        text = f"{where}: {self.verdict or 'lasso dumped'}"
        if self.verdict == "NON-TERMINATING" and (self.approximate or self.warnings):
            # only termination proofs survive over-approximation
            text += " (unconfirmed: the lasso over-approximates the loop)"
        if self.proof:
            text += f" [{self.proof}]"
        if self.warnings:
            text += f" (warning: {'; '.join(self.warnings)})"
        if self.path:
            text += f" -> {self.path}"
        return text


class LassoError(Exception):
    pass


#
# BV -> Int translation
#


def is_loop_var(e: ExprRef) -> bool:
    return (
        e.num_args() == 0
        and e.decl().kind() == Z3_OP_UNINTERPRETED
        and e.decl().name().startswith(LOOP_VAR_PREFIX)
    )


def depends_on_loop_vars(e: ExprRef) -> bool:
    return any(is_loop_var(v) for v in get_vars(e))


class WrapProver:
    """
    Proves, with the bitvector semantics, that an operation cannot wrap around
    under the conditions of a path. Used by the small-constants encoding.

    The conditions of a generalized iteration mention the input symbols (via the
    stem) and the fresh loop variables (via the body). Input symbols never
    change, so facts about them hold at every iteration: using them is sound.
    """

    def __init__(self, conditions: list[BoolRef], timeout_ms: int):
        self.solver = Solver()
        self.solver.set(timeout=timeout_ms)
        self.solver.add(*conditions)
        self.memo: dict[int, bool] = {}

    def valid(self, cond: BoolRef) -> bool:
        cond = simplify(cond)
        if is_true(cond):
            return True
        if is_false(cond):
            return False
        key = cond.get_id()
        if key not in self.memo:
            self.solver.push()
            self.solver.add(Not(cond))
            self.memo[key] = self.solver.check() == unsat
            self.solver.pop()
        return self.memo[key]


class Registry:
    """State shared by all the translation contexts of one lasso."""

    def __init__(self):
        self.aux_counter = 0
        # loop-invariant opaque terms -> (program variable name, width, term)
        self.invariants: dict[int, tuple[str, int, ExprRef]] = {}
        # large literals (small-constants encoding) -> program variable name
        self.big_constants: dict[int, str] = {}
        # set when the translation over-approximates the bitvector semantics
        self.approximate = False

    def fresh(self, prefix: str) -> str:
        self.aux_counter += 1
        return f"{prefix}{self.aux_counter}"

    def invariant(self, e: ExprRef) -> str:
        key = e.get_id()
        if key not in self.invariants:
            width = e.size() if is_bv(e) else 1
            self.invariants[key] = (f"k{len(self.invariants)}", width, e)
        return self.invariants[key][0]

    def big_constant(self, value: int) -> str:
        if value not in self.big_constants:
            self.big_constants[value] = f"c{len(self.big_constants)}"
        return self.big_constants[value]


class Translator:
    """
    Translates bitvector formulas to linear integer SMT-LIB terms.

    One translator per transition disjunct: auxiliary variables and their
    constraints are local to it.

    Two encodings:
    - exact (prover is None): wrap-arounds are encoded exactly, with 2^w
      constants. Suitable for tools with exact arithmetic.
    - small constants (with a prover): no literal exceeds MAX_SMALL_CONSTANT,
      because PaSTTeL represents numbers as doubles (exact up to 2^53 only).
      See docs/loop-termination.md.
    """

    def __init__(
        self,
        registry: Registry,
        names: dict[str, str],
        stem: bool,
        prover: WrapProver | None = None,
    ):
        self.reg = registry
        self.names = names  # loop variable name -> SSA name
        self.stem = stem
        self.prover = prover
        self.aux: list[str] = []
        self.constraints: list[str] = []
        self.memo: dict[int, str] = {}

    @property
    def small(self) -> bool:
        return self.prover is not None

    # helpers

    def _aux(self, width: int | None) -> str:
        name = self.reg.fresh("aux")
        self.aux.append(name)
        if width is not None:
            self.constraints.append(f"(<= 0 {name})")
            upper = 2**width
            if not self.small or upper <= MAX_SMALL_CONSTANT:
                self.constraints.append(f"(< {name} {upper})")
        return name

    def _num(self, value: int) -> str:
        """A literal; large ones become constant program variables if needed."""
        if self.small and value > MAX_SMALL_CONSTANT:
            self.reg.approximate = True
            name = self.reg.big_constant(value)
            return f"{name}_s" if self.stem else name
        return str(value)

    def _wrap(
        self,
        expr: str,
        width: int,
        k_min: int,
        k_max: int | None,
        no_wrap: BoolRef | None = None,
    ) -> str:
        """
        expr mod 2^width, where expr - r = 2^width * k with k in [k_min, k_max].

        `no_wrap` is the bitvector condition under which k = 0.
        """
        m = 2**width

        if self.small:
            # k = 0 proven: the result is the integer expression itself
            if no_wrap is not None and self.prover.valid(no_wrap):
                return expr
            self.reg.approximate = True
            r = self._aux(width)
            if k_min >= 0:
                # only positive wrap-arounds: r = expr - 2^w * k <= expr
                self.constraints.append(f"(<= {r} {expr})")
            elif k_max is not None and k_max <= 0:
                # only borrows: no wrap iff expr >= 0 (no large constant needed)
                self.constraints.append(
                    f"(or (and (<= 0 {expr}) (= {r} {expr})) (< {expr} 0))"
                )
            return r

        r = self._aux(width)
        if k_max is not None and k_max - k_min < MAX_WRAP_CASES:
            cases = []
            for k in range(k_min, k_max + 1):
                lo, hi = m * k, m * (k + 1)
                shifted = expr if k == 0 else f"(- {expr} {lo})"
                cases.append(
                    f"(and (<= {lo} {expr}) (< {expr} {hi}) (= {r} {shifted}))"
                )
            self.constraints.append(
                cases[0] if len(cases) == 1 else f"(or {' '.join(cases)})"
            )
        else:
            k = self._aux(None)
            self.constraints.append(f"(= {r} (- {expr} (* {m} {k})))")
        return r

    def _ite(self, cond: str, a: str, b: str, width: int | None) -> str:
        """Arithmetic if-then-else, which PaSTTeL doesn't parse: a fresh t with
        (cond and t = a) or (not cond and t = b)."""
        t = self._aux(width)
        self.constraints.append(
            f"(or (and {cond} (= {t} {a})) (and (not {cond}) (= {t} {b})))"
        )
        return t

    def _div_const(self, a: str, c: int) -> str:
        """a div c for a constant c > 0: c*q <= a <= c*q + c - 1."""
        if c == 1:
            return a
        q = self._aux(None)
        if self.small and c > MAX_SMALL_CONSTANT:
            self.reg.approximate = True
            # only keep 0 <= q <= a
            self.constraints.append(f"(<= 0 {q})")
            self.constraints.append(f"(<= {q} {a})")
            return q
        self.constraints.append(f"(<= (* {c} {q}) {a})")
        self.constraints.append(f"(<= {a} (+ (* {c} {q}) {c - 1}))")
        return q

    def _rem_const(self, a: str, c: int) -> str:
        if self.small and c > MAX_SMALL_CONSTANT:
            self.reg.approximate = True
            r = self._aux(None)
            self.constraints.append(f"(<= 0 {r})")
            self.constraints.append(f"(<= {r} {a})")
            return r
        return f"(- {a} (* {c} {self._div_const(a, c)}))"

    def _truncate(self, a_term: str, a: BitVecRef, width: int) -> str:
        """a (of a wider sort) mod 2^width."""
        upper = 2**width
        no_wrap = ULT(a, BitVecVal(upper, a.size())) if upper < 2 ** a.size() else None
        k_max = 2 ** (a.size() - width) - 1
        return self._wrap(a_term, width, 0, k_max, no_wrap)

    def _opaque(self, e: ExprRef) -> str:
        """Opaque term: shared constant if loop-invariant, fresh value otherwise."""
        # a free input symbol is represented exactly by a variable; a compound
        # term (keccak, storage read, bitwise operation...) is not
        if e.num_args() > 0:
            self.reg.approximate = True
        width = e.size() if is_bv(e) else 1
        if not self.stem and not depends_on_loop_vars(e):
            return self.reg.invariant(e)
        if self.stem and e.get_id() in self.reg.invariants:
            return self.reg.invariants[e.get_id()][0] + "_s"
        return self._aux(width)

    @staticmethod
    def _const(e: ExprRef) -> int | None:
        return e.as_long() if is_bv_value(e) else None

    # entry points

    def bv(self, e: BitVecRef) -> str:
        key = e.get_id()
        if key not in self.memo:
            self.memo[key] = self._bv(e)
        return self.memo[key]

    def bool(self, e: BoolRef) -> str:
        key = e.get_id()
        if key not in self.memo:
            self.memo[key] = self._bool(e)
        return self.memo[key]

    def any(self, e: ExprRef) -> str:
        """Int term for a bitvector, 0/1 for a boolean."""
        if is_bool(e):
            return self._ite(self.bool(e), "1", "0", 1)
        return self.bv(e)

    # bitvectors

    def _bv(self, e: BitVecRef) -> str:
        w = e.size()
        kind = e.decl().kind()
        args = e.children()

        if kind == Z3_OP_BNUM:
            return self._num(e.as_long())

        if e.num_args() == 0 and kind == Z3_OP_UNINTERPRETED:
            name = e.decl().name()
            if name in self.names:
                return self.names[name]
            return self._opaque(e)

        if kind == Z3_OP_BADD:
            # x + C with C >= 2^(w-1) is x - (2^w - C), e.g. solc's x - 1
            consts = [c for a in args if (c := self._const(a)) is not None]
            neg = sum(2**w - c for c in consts if c >= 2 ** (w - 1))
            if neg and 0 < neg < 2**w and len(consts) < len(args):
                rest = [a for a in args if not (self._const(a) or 0) >= 2 ** (w - 1)]
                rest_expr = rest[0] if len(rest) == 1 else Sum(rest)
                d = BitVecVal(neg, w)
                return self._wrap(
                    f"(- {self.bv(rest_expr)} {self._num(neg)})",
                    w,
                    -1,
                    0,
                    UGE(rest_expr, d),
                )
            terms = " ".join(self.bv(a) for a in args)
            wide = w + len(args).bit_length()
            total = Sum([ZeroExt(wide - w, a) for a in args])
            no_wrap = ULT(total, BitVecVal(2**w, wide))
            return self._wrap(f"(+ {terms})", w, 0, len(args) - 1, no_wrap)

        if kind == Z3_OP_BSUB:
            a, b = args
            return self._wrap(f"(- {self.bv(a)} {self.bv(b)})", w, -1, 0, UGE(a, b))

        if kind == Z3_OP_BNEG:
            return self._wrap(f"(- 0 {self.bv(args[0])})", w, -1, 0, args[0] == 0)

        if kind == Z3_OP_BMUL:
            consts = [c for a in args if (c := self._const(a)) is not None]
            others = [a for a in args if self._const(a) is None]
            if len(others) <= 1:
                coef = 1
                for c in consts:
                    coef *= c
                coef %= 2**w
                if not others:
                    return self._num(coef)
                return self._scale(others[0], coef, w)
            return self._opaque(e)

        if kind == Z3_OP_BSHL and (s := self._const(args[1])) is not None:
            if s >= w:
                return "0"
            return self._scale(args[0], 2**s, w)

        if kind == Z3_OP_BLSHR and (s := self._const(args[1])) is not None:
            if s >= w:
                return "0"
            return self._div_const(self.bv(args[0]), 2**s)

        if kind in (Z3_OP_BUDIV, Z3_OP_BUDIV_I) and (c := self._const(args[1])):
            return self._div_const(self.bv(args[0]), c)

        if kind in (Z3_OP_BUREM, Z3_OP_BUREM_I) and (c := self._const(args[1])):
            return self._rem_const(self.bv(args[0]), c)

        if kind == Z3_OP_BAND:
            # masking with 2^n - 1 is a truncation
            consts = [c for a in args if (c := self._const(a)) is not None]
            others = [a for a in args if self._const(a) is None]
            if len(consts) == 1 and len(others) == 1:
                mask = consts[0]
                if mask & (mask + 1) == 0:
                    n = mask.bit_length()
                    if n >= w:
                        return self.bv(others[0])
                    return self._truncate(self.bv(others[0]), others[0], n)
            return self._opaque(e)

        if kind == Z3_OP_EXTRACT:
            hi, lo = e.params()
            a = args[0]
            if lo == 0 and hi + 1 >= a.size():
                return self.bv(a)
            if lo == 0:
                return self._truncate(self.bv(a), a, hi + 1)
            shifted = self._div_const(self.bv(a), 2**lo)
            if hi + 1 >= a.size():
                return shifted
            # (a >> lo) mod 2^(hi - lo + 1)
            return self._truncate(shifted, LShR(a, lo), hi - lo + 1)

        if kind == Z3_OP_CONCAT:
            acc = None
            for a in args:
                term = self.bv(a)
                if acc is None:
                    acc = term
                elif self.small and 2 ** a.size() > MAX_SMALL_CONSTANT:
                    # the high part is scaled by a large constant
                    zeros = all(self._const(x) == 0 for x in args[:-1])
                    acc = term if zeros else self._opaque(e)
                    if not zeros:
                        return acc
                else:
                    acc = f"(+ (* {2 ** a.size()} {acc}) {term})"
            return acc

        if kind == Z3_OP_ZERO_EXT:
            return self.bv(args[0])

        if kind == Z3_OP_ITE:
            return self._ite(self.bool(args[0]), self.bv(args[1]), self.bv(args[2]), w)

        # dolmos abstractions of nonlinear arithmetic: exact when the divisor is constant
        if kind == Z3_OP_UNINTERPRETED and len(args) == 2:
            name = e.decl().name()
            c = self._const(args[1])
            if name.startswith("f_evm_bvudiv") and c:
                return self._div_const(self.bv(args[0]), c)
            if name.startswith("f_evm_bvurem") and c:
                return self._rem_const(self.bv(args[0]), c)
            if name.startswith("f_evm_bvmul"):
                c0, c1 = self._const(args[0]), self._const(args[1])
                if c0 is not None or c1 is not None:
                    coef, other = (c0, args[1]) if c0 is not None else (c1, args[0])
                    return self._scale(other, coef, w)

        return self._opaque(e)

    def _scale(self, x: BitVecRef, coef: int, w: int) -> str:
        """(coef * x) mod 2^w for a constant coef."""
        if coef == 0:
            return "0"
        if coef == 1:
            return self.bv(x)
        if self.small and coef > MAX_SMALL_CONSTANT:
            self.reg.approximate = True
            r = self._aux(w)
            return r
        wide = w + coef.bit_length()
        no_wrap = ULT(ZeroExt(wide - w, x) * coef, BitVecVal(2**w, wide))
        return self._wrap(f"(* {coef} {self.bv(x)})", w, 0, max(coef - 1, 0), no_wrap)

    # booleans

    def _signed(self, e: BitVecRef) -> str:
        w = e.size()
        a = self.bv(e)
        return self._ite(f"(>= {a} {2 ** (w - 1)})", f"(- {a} {2**w})", a, None)

    def _signed_cmp(self, op: str, a: BitVecRef, b: BitVecRef) -> str:
        if self.small:
            # without large constants: exact only when both operands are
            # provably non-negative, in which case it is the unsigned comparison
            w = a.size()
            half = BitVecVal(2 ** (w - 1), w)
            if self.prover.valid(And(ULT(a, half), ULT(b, half))):
                return f"({op} {self.bv(a)} {self.bv(b)})"
            self.reg.approximate = True
            aux = self._aux(1)
            return f"(= {aux} 1)"
        return f"({op} {self._signed(a)} {self._signed(b)})"

    def _bool(self, e: BoolRef) -> str:
        kind = e.decl().kind()
        args = e.children()

        if kind == Z3_OP_TRUE:
            return "true"
        if kind == Z3_OP_FALSE:
            return "false"
        if kind == Z3_OP_NOT:
            return f"(not {self.bool(args[0])})"
        if kind == Z3_OP_AND:
            return f"(and {' '.join(self.bool(a) for a in args)})"
        if kind == Z3_OP_OR:
            return f"(or {' '.join(self.bool(a) for a in args)})"
        if kind == Z3_OP_IMPLIES:
            return f"(or (not {self.bool(args[0])}) {self.bool(args[1])})"
        if kind in (Z3_OP_IFF, Z3_OP_EQ) and is_bool(args[0]):
            a, b = self.bool(args[0]), self.bool(args[1])
            return f"(or (and {a} {b}) (and (not {a}) (not {b})))"
        if kind == Z3_OP_XOR:
            a, b = self.bool(args[0]), self.bool(args[1])
            return f"(or (and {a} (not {b})) (and (not {a}) {b}))"
        if kind == Z3_OP_ITE:
            c, a, b = (self.bool(x) for x in args)
            return f"(or (and {c} {a}) (and (not {c}) {b}))"

        if kind == Z3_OP_EQ:
            return f"(= {self.bv(args[0])} {self.bv(args[1])})"
        if kind == Z3_OP_DISTINCT and len(args) == 2:
            return f"(not (= {self.bv(args[0])} {self.bv(args[1])}))"

        unsigned = {Z3_OP_ULT: "<", Z3_OP_ULEQ: "<=", Z3_OP_UGT: ">", Z3_OP_UGEQ: ">="}
        if kind in unsigned:
            return f"({unsigned[kind]} {self.bv(args[0])} {self.bv(args[1])})"

        signed = {Z3_OP_SLT: "<", Z3_OP_SLEQ: "<=", Z3_OP_SGT: ">", Z3_OP_SGEQ: ">="}
        if kind in signed:
            return self._signed_cmp(signed[kind], args[0], args[1])

        # opaque boolean: encoded as an Int in {0, 1}
        self.reg.approximate = True
        b = self._aux(1)
        return f"(= {b} 1)"

    def conj(self, parts: list[str]) -> str:
        parts = [p for p in parts + self.constraints if p != "true"]
        if not parts:
            return "true"
        if len(parts) == 1:
            return parts[0]
        return f"(and {' '.join(parts)})"


#
# lasso construction
#


def slice_conditions(conditions: list[BoolRef], seeds: list[ExprRef]) -> list[BoolRef]:
    """Keeps the conditions transitively sharing variables with the seeds."""
    cond_vars = [{v.get_id() for v in get_vars(c)} for c in conditions]
    wanted = {v.get_id() for s in seeds for v in get_vars(s)}
    kept: set[int] = set()
    changed = True
    while changed:
        changed = False
        for i, vs in enumerate(cond_vars):
            if i not in kept and vs & wanted:
                kept.add(i)
                wanted |= vs
                changed = True
    return [c for i, c in enumerate(conditions) if i in kept]


@dataclass
class BodyPath:
    conditions: list[BoolRef]  # conditions added during the iteration
    outputs: list[ExprRef]  # new values of the loop variables (in order)
    context: list[BoolRef] = field(default_factory=list)  # all path conditions


_LARGE_LITERAL_RE = re.compile(r"(?<![\w.])\d{16,}(?![\w.])")


def check_small_constants(formula: str) -> None:
    for m in _LARGE_LITERAL_RE.finditer(formula):
        if int(m.group(0)) > MAX_SMALL_CONSTANT:
            raise LassoError(f"internal error: large literal {m.group(0)} in the lasso")


def build_lasso(
    loop_vars: list[str],
    widths: list[int],
    initial_values: list[ExprRef],
    stem_conditions: list[BoolRef],
    guard: BoolRef | None,
    bodies: list[BodyPath],
    exact_constants: bool = False,
    stem_context: list[BoolRef] | None = None,
    prover_timeout_ms: int = 1000,
    complete: bool = False,
) -> dict:
    """
    loop_vars[i]: name of the i-th fresh loop variable (lasso_v...);
    the branching condition is the last loop variable (0/1 or raw word), and
    `guard` (over the loop variables) must hold to stay in the loop.
    """
    small = not exact_constants
    reg = Registry()
    prog = [f"v{i}" for i in range(len(loop_vars))]
    in_names = {lv: f"{p}_i" for lv, p in zip(loop_vars, prog, strict=True)}

    def upper(name: str, w: int) -> list[str]:
        if small and 2**w > MAX_SMALL_CONSTANT:
            return []
        return [f"(< {name} {2**w})"]

    # facts for the wrap-around prover: the current iteration was entered by
    # taking the loop branch at the end of a previous iteration (there is one,
    # since the unrolling bound was reached). Only valid if the body paths are
    # complete, as the previous iteration may have followed any of them.
    previous: list[BoolRef] = []
    if small and complete and bodies:
        cur = [BitVec(name, 256) for name in loop_vars]
        prev = [BitVec(f"{name}_prev", 256) for name in loop_vars]
        pairs = list(zip(cur, prev, strict=True))
        previous.append(
            Or(
                *[
                    And(
                        *[substitute(c, *pairs) for c in b.conditions],
                        *[
                            v == substitute(out, *pairs)
                            for v, out in zip(cur, b.outputs, strict=True)
                        ],
                    )
                    for b in bodies
                ]
            )
        )

    # loop transition: one disjunct per body path
    disjuncts = []
    loop_aux: list[str] = []
    for body in bodies:
        prover = (
            WrapProver([*body.context, *previous], prover_timeout_ms) if small else None
        )
        tr = Translator(reg, in_names, stem=False, prover=prover)
        parts = [tr.bool(guard)] if guard is not None else []
        parts += [tr.bool(c) for c in body.conditions]
        for p, out in zip(prog, body.outputs, strict=True):
            parts.append(f"(= {p}_o {tr.any(out)})")
        disjuncts.append(tr.conj(parts))
        loop_aux += tr.aux

    ranges = []
    for p, w in zip(prog, widths, strict=True):
        for suffix in ("_i", "_o"):
            ranges += [f"(<= 0 {p}{suffix})", *upper(f"{p}{suffix}", w)]
    for name, w, _ in reg.invariants.values():
        ranges += [f"(<= 0 {name})", *upper(name, w)]

    body_formula = (
        disjuncts[0] if len(disjuncts) == 1 else f"(or {' '.join(disjuncts)})"
    )
    loop_formula = f"(and {' '.join(ranges)} {body_formula})"

    invariant_names = [name for name, _, _ in reg.invariants.values()]

    # stem: initial values of the loop variables and of the loop invariants
    prover = (
        WrapProver(stem_context or stem_conditions, prover_timeout_ms)
        if small
        else None
    )
    tr = Translator(reg, {}, stem=True, prover=prover)
    parts = [tr.bool(c) for c in stem_conditions]
    for p, init in zip(prog, initial_values, strict=True):
        parts.append(f"(= {p}_s {tr.any(init)})")
    for name, _, term in list(reg.invariants.values()):
        parts.append(f"(= {name}_s {tr.any(term)})")
    stem_ranges = []
    for p, w in zip(prog, widths, strict=True):
        stem_ranges += [f"(<= 0 {p}_s)", *upper(f"{p}_s", w)]
    for name, w, _ in reg.invariants.values():
        stem_ranges += [f"(<= 0 {name}_s)", *upper(f"{name}_s", w)]
    stem_formula = tr.conj(stem_ranges + parts)

    # large literals are constant program variables, identical in the stem and
    # the loop; their only known facts are positivity and their relative order
    big_names = [reg.big_constants[v] for v in sorted(reg.big_constants)]
    order = [f"(<= 0 {big_names[0]})"] if big_names else []
    order += [f"(< {a} {b})" for a, b in zip(big_names, big_names[1:], strict=False)]
    if order:
        loop_formula = f"(and {' '.join(order)} {loop_formula})"
        stem_order = [re.sub(r"\b(c\d+)\b", r"\1_s", o) for o in order]
        stem_formula = f"(and {' '.join(stem_order)} {stem_formula})"

    if small:
        check_small_constants(loop_formula)
        check_small_constants(stem_formula)

    all_vars = prog + invariant_names + big_names
    constants = invariant_names + big_names
    return reg.approximate, {
        "program_vars": all_vars,
        "var_types": {v: "Int" for v in all_vars},
        "stem": [
            {
                "source": "entry",
                "target": "head",
                "formula": stem_formula,
                "in_vars": {v: f"{v}_e" for v in all_vars},
                "out_vars": {v: f"{v}_s" for v in all_vars},
                "aux_vars": tr.aux,
                "assigned_vars": all_vars,
            }
        ],
        "loop": [
            {
                "source": "head",
                "target": "head",
                "formula": loop_formula,
                "in_vars": {**{p: f"{p}_i" for p in prog}, **{k: k for k in constants}},
                "out_vars": {
                    **{p: f"{p}_o" for p in prog},
                    **{k: k for k in constants},
                },
                "aux_vars": loop_aux,
                "assigned_vars": prog,
            }
        ],
    }


def fresh_loop_var(index: int, uid: int) -> BitVecRef:
    return BitVec(f"{LOOP_VAR_PREFIX}{uid}_{index}", 256)


def as_z3(x) -> ExprRef:
    return x.as_z3() if hasattr(x, "as_z3") else x


def same_term(a, b) -> bool:
    if a is b:
        return True
    za, zb = as_z3(a), as_z3(b)
    if is_bool(za) != is_bool(zb):
        return False
    return za.eq(zb)


def branch_taken(cond: ExprRef, direction: bool) -> BoolRef:
    """The condition for a JUMPI on `cond` to take the `direction` branch."""
    if is_bool(cond):
        return cond if direction else simplify(Not(cond))
    return cond != 0 if direction else cond == 0


#
# PaSTTeL
#

_VERDICT_RE = re.compile(r"OVERALL RESULT:\s*(\S+)")
_PROOF_RE = re.compile(
    r"^(\S+\([^)]*\)|\S+)\s+(TERMINATING|NON-TERMINATING)\s+[\d.]+\s+(.*)$", re.M
)


def run_pasttel(binary: str, lasso_path: str, timeout: int) -> tuple[str, str | None]:
    try:
        proc = subprocess.run(
            [binary, "-a", "both", "-t", str(timeout), lasso_path],
            capture_output=True,
            text=True,
            timeout=timeout + 10,
        )
    except subprocess.TimeoutExpired:
        return "TIMEOUT", None
    except OSError as err:
        return f"ERROR ({err})", None

    output = proc.stdout + proc.stderr
    with open(lasso_path.removesuffix(".json") + ".pasttel.txt", "w") as f:
        f.write(output)

    verdict = m.group(1) if (m := _VERDICT_RE.search(output)) else "UNKNOWN"
    proof = None
    for m in _PROOF_RE.finditer(output):
        if m.group(2) == verdict:
            proof = f"{m.group(1)}: {m.group(3).strip()}"
            break
    return verdict, proof


def write_lasso(out_dir: str, name: str, lasso: dict, meta: dict) -> str:
    os.makedirs(out_dir, exist_ok=True)
    path = os.path.join(out_dir, f"{name}.json")
    with open(path, "w") as f:
        json.dump(lasso, f, indent=2)
    with open(os.path.join(out_dir, f"{name}.meta.json"), "w") as f:
        json.dump(meta, f, indent=2, default=str)
    return path
