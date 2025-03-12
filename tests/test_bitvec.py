import pytest
from z3 import And, BitVec, BitVecVal, BoolVal, Concat, Or, eq, simplify

from halmos.bitvec import FALSE, TRUE
from halmos.bitvec import HalmosBitVec as BV
from halmos.bitvec import HalmosBool as Bool
from halmos.bytevec import Chunk
from halmos.exceptions import NotConcreteError

a, b = Bool("a"), Bool("b")
x, y = BV("x"), BV("y")


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
    hbool = Bool(hbv)
    assert bool(hbool)
    assert bool(hbv.is_non_zero())
    assert not bool(hbv.is_zero())

    hbv = BV(0)
    hbool = Bool(hbv)
    assert not bool(hbool)
    assert not bool(hbv.is_non_zero())
    assert bool(hbv.is_zero())

    hbv = BV(BitVec("x", 256))
    hbool = Bool(hbv)

    with pytest.raises(NotConcreteError):
        bool(hbool)

    with pytest.raises(NotConcreteError):
        bool(hbv.is_non_zero())


def test_bool_wrapping():
    assert Bool(True) == TRUE
    assert Bool(False) == FALSE
    assert TRUE is Bool(True)
    assert FALSE is Bool(False)
    assert TRUE.is_true
    assert not TRUE.is_false
    assert FALSE.is_false
    assert not FALSE.is_true
    assert Bool(TRUE) == TRUE
    assert TRUE is Bool(TRUE)
    assert bool(TRUE)
    assert not bool(TRUE.neg())

    # BoolVal is lowered to True/False
    assert Bool(BoolVal(True), do_simplify=True) == TRUE
    assert Bool(BoolVal(True), do_simplify=False) == TRUE

    x = BitVec("x", 256)
    tautology = x == x

    # tautology is lowered to True, but only when do_simplify is True
    assert Bool(tautology, do_simplify=True) == TRUE
    assert Bool(tautology, do_simplify=True) is TRUE
    assert Bool(tautology, do_simplify=False) != TRUE


def test_bool_to_bitvec_conversion():
    hbool = TRUE
    hbv = BV(hbool)
    assert hbv.value == 1

    hbool = FALSE
    hbv = BV(hbool)
    assert hbv.value == 0

    hbool = Bool(BitVec("x", 256) != 0)
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
    assert x.eq(x) == TRUE
    assert x.eq(y) == x.eq(y)
    assert x.eq(y) != y.eq(x)


def test_bool_is_zero():
    assert BV(0).is_zero().is_true
    assert BV(0).is_non_zero().is_false

    assert BV(1).is_zero().is_false
    assert BV(1).is_non_zero().is_true

    assert Bool(False).is_zero().is_true
    assert Bool(False).is_non_zero().is_false

    assert Bool(True).is_zero().is_false
    assert Bool(True).is_non_zero().is_true


def test_bv_to_chunk():
    hbv = BV(2**256 - 1)
    chunk = Chunk.wrap(hbv)
    assert len(chunk) == 32
    assert chunk[0] == 0xFF
    assert chunk[31] == 0xFF


def test_in_operator():
    x = BV(42)
    assert x in [BV(0), BV(42), BV(43)]

    assert BV("x") not in [x, BV(43)]

    assert BV("y") in [BV("x"), BV("y"), BV("z")]

    # can not compare directly to ints
    assert x not in [0, 42, 43]


def test_bitwise_and():
    assert TRUE.bitwise_and(TRUE) == TRUE
    assert TRUE.bitwise_and(FALSE) == FALSE
    assert FALSE.bitwise_and(TRUE) == FALSE
    assert FALSE.bitwise_and(FALSE) == FALSE

    assert TRUE.bitwise_and(a) == a
    assert a.bitwise_and(TRUE) == a

    assert FALSE.bitwise_and(a) == FALSE
    assert a.bitwise_and(FALSE) == FALSE

    assert a.bitwise_and(b) == Bool(And(a.as_z3(), b.as_z3()))


def test_bitwise_or():
    assert TRUE.bitwise_or(TRUE) == TRUE
    assert TRUE.bitwise_or(FALSE) == TRUE
    assert FALSE.bitwise_or(TRUE) == TRUE
    assert FALSE.bitwise_or(FALSE) == FALSE

    assert TRUE.bitwise_or(a) == TRUE
    assert a.bitwise_or(TRUE) == TRUE

    assert FALSE.bitwise_or(a) == a
    assert a.bitwise_or(FALSE) == a

    assert a.bitwise_or(b) == Bool(Or(a.as_z3(), b.as_z3()))


def test_bitwise_xor():
    assert TRUE.bitwise_xor(TRUE) == FALSE
    assert TRUE.bitwise_xor(FALSE) == TRUE
    assert FALSE.bitwise_xor(TRUE) == TRUE
    assert FALSE.bitwise_xor(FALSE) == FALSE

    assert TRUE.bitwise_xor(a) == a.bitwise_not()
    assert a.bitwise_xor(TRUE) == a.bitwise_not()

    assert FALSE.bitwise_xor(a) == a
    assert a.bitwise_xor(FALSE) == a

    assert a.bitwise_xor(b) == Bool(a.as_z3() ^ b.as_z3())
