from textwrap import dedent

import pytest
from z3 import BitVec, BitVecVal, Concat, eq, simplify

from halmos.bitvec import HalmosBitVec as BV
from halmos.bitvec import HalmosBool
from halmos.exceptions import NotConcreteError


@pytest.mark.parametrize("value", [0xFF00, 0xFFFF, -1, -2])
def test_truncation_concrete(value):
    hbv = BV(value, size=8)
    zbv = BitVecVal(value, 8)
    assert int(hbv) == zbv.as_long()


def test_truncation_symbolic():
    y = BitVec("y", 8)
    x = Concat(BitVecVal(0, 248), y)

    hbv = BV(x, size=8)
    z = simplify(hbv.value)
    assert eq(z, y)


def test_truncation_bv():
    x = BV(BitVecVal(0x12345678, 32))
    y = BV(x, size=8)
    assert y.value == 0x78

    z = BV(x, size=32)
    assert z.value == 0x12345678
    assert z is x


def test_conversion_success():
    hbv = BV(42)
    assert int(hbv) == 42
    assert str(hbv) == "42"

    hbv = BV(-1, size=8)
    assert int(hbv) == 0xFF
    assert hbv == BV(0xFF, size=8)


def test_conversion_failure():
    with pytest.raises(NotConcreteError):
        hbv = BV(BitVec("x", 256))
        int(hbv)


def test_equality():
    x = BV("x")
    y = BV("y")
    assert x != y
    assert x == x
    assert x.add(y) == x.add(y)
    assert x.add(y) != y.add(x)


def test_left_shift():
    assert BV(42).lshl(BV(2)) == BV(168)
    assert BV(42).lshl(BV(256)) == BV(0)
    assert BV(42).lshl(BV(0)) == BV(42)

    assert BV(42).lshl(BV("x")) == BV(42 << BitVec("x", 256))

    assert BV("x").lshl(BV(256)) == BV(0)
    assert BV("x").lshl(BV(0)) == BV("x")
    assert BV("x").lshl(BV("y")) == BV(BitVec("x", 256) << BitVec("y", 256))


def test_bitvec_to_bool_conversion():
    hbv = BV(42)
    hbool = HalmosBool(hbv)
    assert bool(hbool)
    assert bool(hbv.is_non_zero())
    assert not bool(hbv.is_zero())

    hbv = BV(0)
    hbool = HalmosBool(hbv)
    assert not bool(hbool)
    assert not bool(hbv.is_non_zero())
    assert bool(hbv.is_zero())

    hbv = BV(BitVec("x", 256))
    hbool = HalmosBool(hbv)

    with pytest.raises(NotConcreteError):
        bool(hbool)

    with pytest.raises(NotConcreteError):
        bool(hbv.is_non_zero())


def test_bool_wrapping():
    hbool = HalmosBool(True)
    hbool2 = HalmosBool(hbool)
    assert hbool == hbool2
    assert hbool2 is hbool
    assert bool(hbool2)
    assert not bool(hbool2.neg())


def test_bool_to_bitvec_conversion():
    hbool = HalmosBool(True)
    hbv = BV(hbool)
    assert hbv.value == 1

    hbool = HalmosBool(False)
    hbv = BV(hbool)
    assert hbv.value == 0

    hbool = HalmosBool(BitVec("x", 256) != 0)
    hbv = BV(hbool)
    assert hbv.is_symbolic
    assert hbv.size == 1

    hbv = BV(hbool, size=256)
    assert hbv.is_symbolic
    assert hbv.size == 256


def timeme(*args, **kwargs) -> tuple[int, float]:
    import timeit

    # Set default value for 'number' if not provided
    number = kwargs.pop("number", 1000000)

    # Pass all arguments to timeit.repeat
    times = timeit.repeat(*args, repeat=5, number=number, **kwargs)
    best_time = min(times)
    usec_per_loop = best_time / number * 1e6  # Convert seconds to microseconds
    return number, usec_per_loop


def timeme_report(*args, **kwargs):
    number, usec_per_loop = timeme(*args, **kwargs)
    print(f"{number} loops, best of 5: {usec_per_loop:.3f} usec per loop")


def compare(stmts=None, *args, **kwargs):
    results = [(stmt, timeme(*args, stmt=stmt, **kwargs)) for stmt in stmts]
    results = sorted(results, key=lambda x: x[1][1])

    print("Best: ", end="")
    baseline = results[0][1][1]
    for stmt, result in results:
        print(stmt)
        base_text = f"    {result[0]} loops, best of 5: {result[1]:.3f} usec per loop"
        if result[1] == baseline:
            print(base_text)
        else:
            print(f"{base_text} ({result[1] / baseline:.3f}x)")
        print()


compare(
    setup=dedent("""
        import random
        from z3 import BitVec, BitVecRef, BitVecVal, URem, Extract, ZeroExt, simplify
        from halmos.bitvec import HalmosBitVec as BV
        from halmos.utils import con

        def addmod(x, y, z):
            r1 = simplify(ZeroExt(8, x)) + simplify(ZeroExt(8, y))
            r2 = URem(r1, simplify(ZeroExt(8, z)))
            return Extract(255, 0, r2)
    """),
    stmts=[
        "BV(4).addmod(BV(1), BV(3)) == BV(2)",
        "addmod(con(4), con(1), con(3)) == con(2)",
    ],
    number=10**4,
)
