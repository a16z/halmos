# SPDX-License-Identifier: AGPL-3.0

import copy
import gc
import threading

import pytest
import z3

from dolmos import zfast
from dolmos.zfast import (
    ULT,
    And,
    BitVec,
    BitVecVal,
    BoolVal,
    Concat,
    Extract,
    Function,
    If,
    Not,
    Or,
    Select,
    Store,
    ZeroExt,
    eq,
    is_app_of,
    is_bv_value,
    is_const,
    is_expr_var,
    is_false,
    is_true,
    simplify,
)


def test_identical_terms_are_identical_objects():
    x, y = BitVec("zf_x", 256), BitVec("zf_y", 256)
    assert BitVec("zf_x", 256) is x
    assert x + y is x + y
    assert Extract(7, 0, x) is Extract(7, 0, x)
    assert Concat(x, y) is Concat(x, y)
    assert ULT(x, y) is ULT(x, y)
    assert BitVecVal(42, 8) is BitVecVal(42, 8)
    assert BitVecVal(-1, 8) is BitVecVal(255, 8)
    assert BoolVal(True) is BoolVal(True)
    assert x + y is not y + x


def test_same_terms_as_z3py():
    zx, zy = z3.BitVec("zf_x", 256), z3.BitVec("zf_y", 256)
    x, y = BitVec("zf_x", 256), BitVec("zf_y", 256)
    f = Function("zf_f", z3.BitVecSort(256), z3.BitVecSort(8))
    zf = z3.Function("zf_f", z3.BitVecSort(256), z3.BitVecSort(8))
    pairs = [
        (x + y, zx + zy),
        (x - 1, zx - 1),
        (1 - x, 1 - zx),
        (x * y, zx * zy),
        (x & y | ~x ^ -y, zx & zy | ~zx ^ -zy),
        (x >> 3, zx >> 3),
        (x << y, zx << zy),
        (x / y, zx / zy),
        (x % y, zx % zy),
        (x < y, zx < zy),
        (x >= y, zx >= zy),
        (x == y, zx == zy),
        (x != y, zx != zy),
        (ULT(x, y), z3.ULT(zx, zy)),
        (Extract(15, 8, x), z3.Extract(15, 8, zx)),
        (Concat(x, y, x), z3.Concat(zx, zy, zx)),
        (ZeroExt(8, x), z3.ZeroExt(8, zx)),
        (If(x == y, x, y), z3.If(zx == zy, zx, zy)),
        (And(x == y, ULT(x, y)), z3.And(zx == zy, z3.ULT(zx, zy))),
        (Or(x == y, Not(ULT(x, y))), z3.Or(zx == zy, z3.Not(z3.ULT(zx, zy)))),
        (f(x), zf(zx)),
        (simplify(x + 0), z3.simplify(zx + 0)),
        (
            simplify(Extract(7, 0, Concat(x, y))),
            z3.simplify(z3.Extract(7, 0, z3.Concat(zx, zy))),
        ),
    ]
    for ours, theirs in pairs:
        assert isinstance(ours, zfast._Interned), theirs
        assert ours.eq(theirs), theirs
        assert theirs.eq(ours), theirs
        assert hash(ours) == hash(theirs), theirs
        assert ours.get_id() == theirs.get_id(), theirs
        assert ours.sexpr() == theirs.sexpr(), theirs


def test_structure():
    x, y = BitVec("zf_x", 256), BitVec("zf_y", 256)
    t = x + y
    assert t.num_args() == 2
    assert t.arg(0) is x and t.arg(1) is y
    assert t.children() == [x, y]
    assert t.decl().kind() == z3.Z3_OP_BADD
    assert t.size() == 256
    assert is_app_of(t, z3.Z3_OP_BADD)
    assert is_const(x) and is_expr_var(x)
    assert not is_const(t)
    assert is_const(BitVecVal(1, 8)) and not is_expr_var(BitVecVal(1, 8))
    assert is_bv_value(BitVecVal(1, 8)) and not is_bv_value(x)
    assert BitVecVal(2**255, 256).as_long() == 2**255
    assert z3.is_bv(x) and isinstance(x, z3.BitVecRef)
    assert isinstance(BitVecVal(1, 8), z3.BitVecNumRef)
    assert isinstance(x == y, z3.BoolRef)


def test_booleans():
    x, y = BitVec("zf_x", 256), BitVec("zf_y", 256)
    assert is_true(BoolVal(True)) and is_false(BoolVal(False))
    assert is_true(simplify(x == x))
    assert not is_true(x == y) and not is_false(x == y)
    # as in z3py: the truth value of an equality is the identity of its sides
    assert bool(x == x)
    assert not bool(x == y)
    with pytest.raises(z3.Z3Exception):
        bool(ULT(x, y))
    assert eq(x, x) and not eq(x, y)
    assert eq(x, z3.BitVec("zf_x", 256))


def test_dictionary_keys():
    x, y = BitVec("zf_x", 256), BitVec("zf_y", 256)
    d = {ULT(x, y): 1}
    assert ULT(x, y) in d
    assert ULT(y, x) not in d
    # a z3py object of the same term finds the entry, and conversely
    assert z3.ULT(z3.BitVec("zf_x", 256), z3.BitVec("zf_y", 256)) in d
    assert ULT(x, y) in {z3.ULT(z3.BitVec("zf_x", 256), z3.BitVec("zf_y", 256)): 1}


def test_copies_are_the_term_itself():
    x = BitVec("zf_x", 256)
    assert copy.deepcopy(x) is x
    assert copy.copy(x) is x
    assert copy.deepcopy([x + 1])[0] is x + 1


def test_arrays():
    a = zfast.Array("zf_a", z3.BitVecSort(256), z3.BitVecSort(8))
    i = BitVec("zf_i", 256)
    v = BitVecVal(7, 8)
    assert isinstance(a, zfast.InternedArray)
    assert Select(Store(a, i, v), i) is Select(Store(a, i, v), i)
    assert a[i] is Select(a, i)
    assert simplify(Select(Store(a, i, v), i)) is v


def test_fallbacks():
    x = BitVec("zf_x", 256)
    # python values are coerced by z3py, and the result is interned
    assert isinstance(If(x == 1, 1, x), zfast.InternedBitVec)
    assert ULT(x, 2) is ULT(x, BitVecVal(2, 256))
    assert isinstance(And([x == 1, x == 2]), zfast.InternedBool)
    assert isinstance(simplify(x + 1, som=True), zfast._Interned)
    # errors are those of z3py
    with pytest.raises(z3.Z3Exception):
        x + BitVec("zf_b", 8)
    # terms of other contexts are left to z3py
    ctx = z3.Context()
    assert not isinstance(x.translate(ctx), zfast._Interned)


def test_solver_accepts_interned_terms():
    x, y = BitVec("zf_x", 256), BitVec("zf_y", 256)
    s = z3.Solver()
    s.add(ULT(x, y), x == 5)
    assert s.check() == z3.sat
    assert s.model().eval(x).as_long() == 5
    assert s.check(ULT(y, x)) == z3.unsat


def test_release_of_dead_terms():
    x = BitVec("zf_x", 256)
    zfast._drain()

    terms = [x + BitVecVal(i, 256) for i in range(1000, 1100)]
    addresses = [t._p for t in terms]
    assert all(p in zfast._table for p in addresses)

    del terms
    gc.collect()
    # the objects are gone, their references are released later, by _drain()
    assert not any(p in zfast._table for p in addresses)
    assert sum(p in addresses for p in zfast._pending) == len(addresses)
    zfast._drain()
    assert not zfast._pending

    # the same terms can be built again
    assert (x + BitVecVal(1000, 256)).arg(0) is x


def test_dead_terms_are_not_released_from_other_threads():
    x = BitVec("zf_x", 256)
    zfast._drain()
    box = [x * BitVecVal(i, 256) for i in range(2000, 2050)]

    def worker():
        box.clear()
        gc.collect()

    t = threading.Thread(target=worker)
    t.start()
    t.join()
    # nothing was released by the thread: the addresses are only queued
    assert len(zfast._pending) >= 50
    zfast._drain()


def test_z3py_objects_can_be_released_from_other_threads():
    """objects that are not interned are released by z3py itself, from any thread"""
    x = z3.BitVec("zf_t", 64)
    terms = [[x + i for i in range(2000)] for _ in range(40)]

    def release():
        while terms:
            terms.pop().clear()

    t = threading.Thread(target=release)
    t.start()
    n = 0
    while t.is_alive():
        s = z3.Solver()
        s.add(z3.ULT(x + n, 1000), x != n)
        assert s.check() == z3.sat
        n += 1
    t.join()
