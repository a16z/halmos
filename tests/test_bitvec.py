import pytest
from z3 import BitVec, BitVecVal, BoolVal, Concat, eq, simplify

from halmos.bitvec import HalmosBitVec as BV
from halmos.bitvec import HalmosBool
from halmos.bytevec import Chunk
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
    assert HalmosBool(True) == HalmosBool.TRUE
    assert HalmosBool(False) == HalmosBool.FALSE
    assert HalmosBool(True) is HalmosBool.TRUE
    assert HalmosBool(False) is HalmosBool.FALSE
    assert HalmosBool(True).is_true
    assert not HalmosBool(True).is_false
    assert HalmosBool(False).is_false
    assert not HalmosBool(False).is_true
    assert HalmosBool(True) == HalmosBool(HalmosBool(True))
    assert HalmosBool(True) is HalmosBool(HalmosBool(True))
    assert bool(HalmosBool(True))
    assert not bool(HalmosBool(True).neg())

    # BoolVal is lowered to True/False
    assert HalmosBool(True) == HalmosBool(BoolVal(True), do_simplify=True)
    assert HalmosBool(True) == HalmosBool(BoolVal(True), do_simplify=False)

    x = BitVec("x", 256)
    tautology = x == x

    # tautology is lowered to True, but only when do_simplify is True
    assert HalmosBool(True) == HalmosBool(tautology, do_simplify=True)
    assert HalmosBool(True) != HalmosBool(tautology, do_simplify=False)


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


def test_bool_eq():
    x = BV("x")
    y = BV("y")
    assert x.sgt(y) == x.sgt(y)
    assert x.eq(x) == HalmosBool(True)
    assert x.eq(y) == x.eq(y)
    assert x.eq(y) != y.eq(x)


def test_bv_to_chunk():
    hbv = BV(2**256 - 1)
    chunk = Chunk.wrap(hbv)
    assert len(chunk) == 32
    assert chunk[0] == 0xFF
    assert chunk[31] == 0xFF
