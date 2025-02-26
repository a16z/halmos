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


# compare(
#     setup=dedent("""
#         import random
#         from z3 import BitVec, BitVecRef, BitVecVal
#         from halmos.bitvec import HalmosBool,BV, bitwise_and
#         from halmos.utils import EVM

#         def bitwise_preconvert(op, x, y):
#             # only convert to BV if one of the operands is a bool
#             if isinstance(x, HalmosBool) and isinstance(y, BV):
#                 return bitwise_preconvert(op, BV(x), y)

#             elif isinstance(x, BV) and isinstance(y, HalmosBool):
#                 return bitwise_preconvert(op, x, BV(y))

#             else:
#                 if op == EVM.AND:
#                     return x and y
#                 elif op == EVM.OR:
#                     return x or y
#                 elif op == EVM.XOR:
#                     return x ^ y
#                 else:
#                     raise ValueError(op, x, y)


#         def bitwise_flexible(op, x, y):
#             if op == EVM.AND:
#                 bitwise_and(x, y)
#             # elif op == EVM.OR:
#             #     bitwise_or(x, y)
#             # elif op == EVM.XOR:
#             #     bitwise_xor(x, y)
#             # else:
#             #     raise ValueError(op, x, y)
#     """),
#     stmts=[
#         "bitwise_preconvert(EVM.AND, HalmosBool(True), HalmosBool(True))",
#         "bitwise_preconvert(EVM.AND, HalmosBool(True), BV(42))",
#         "bitwise_preconvert(EVM.AND, BV(42), BV(68))",
#         "bitwise_flexible(EVM.AND, HalmosBool(True), BV(42))",
#         "bitwise_flexible(EVM.AND, HalmosBool(True), HalmosBool(True))",
#         "bitwise_flexible(EVM.AND, BV(42), BV(68))",
#     ],
#     number=10**4
# )
