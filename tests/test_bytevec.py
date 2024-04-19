import pytest

from z3 import BitVec, BitVecVal, Extract

from halmos.bytevec import ByteVec, concat, defrag, OOBReads
from halmos.exceptions import HalmosException


### test helpers


def test_defrag():
    assert defrag([]) == []
    assert defrag([b"hello"]) == [b"hello"]
    assert defrag([b"hello", b"world"]) == [b"helloworld"]
    assert defrag([b"hello", b"world", b"!"]) == [b"helloworld!"]

    # defrag doesn't automatically convert bitvecvals to bytes
    mixed = [b"hello", BitVecVal(int.from_bytes(b"world"), 30), b"!"]
    assert defrag(mixed) == mixed

    x, y, z = (BitVec(_, 8) for _ in "xyz")
    assert defrag([x]) == [x]
    assert defrag([x, y]) == [concat([x, y])]
    assert defrag([x, y, z]) == [concat([x, y, z])]


### test bytevec constructor


def test_bytevec_constructor_nodata():
    vec = ByteVec()
    assert len(vec) == 0
    assert vec._data == []
    assert vec._well_formed()


def test_bytevec_constructor_bytes():
    vec = ByteVec(b"hello")
    assert len(vec) == 5
    assert vec._data == [b"hello"]
    assert vec._well_formed()


def test_bytevec_constructor_bitvecvalue():
    # when we use a concrete bitvecval
    vec = ByteVec(BitVecVal(0x1234, 16))
    assert len(vec) == 2

    # then the bitvecval has been internally converted to bytes
    assert vec._data == [b"\x12\x34"]
    assert vec._well_formed()


def test_bytevec_constructor_bitvec():
    # when we use a symbolic bitvec
    x = BitVec("x", 16)
    vec = ByteVec(x)
    assert len(vec) == 2

    # then the bitvec is stored as-is
    assert vec._data == [x]
    assert vec._well_formed()


def test_bytevec_constructor_concat():
    # when we use a mixed concat expression
    x = BitVec("x", 16)
    vec = ByteVec(concat([BitVecVal(0, 16), x]))
    assert len(vec) == 4

    # then the concat expression has been unwrapped
    assert vec._data == [b"\x00\x00", x]
    assert vec._well_formed()


def test_bytevec_constructor_hexstr():
    vec = ByteVec("deadbeef")
    assert len(vec) == 4
    assert vec._data == [b"\xde\xad\xbe\xef"]
    assert vec._well_formed()


def test_bytevec_constructor_list():
    vec = ByteVec([b"hello", BitVecVal(0x1234, 16)])
    assert len(vec) == 7

    # we expect the output to be lowered to bytes and defragged
    assert vec._data == [b"hello\x12\x34"]
    assert vec._well_formed()


### test bytevec behavior


def test_bytevec_empty_should_be_falsy():
    for vec in ByteVec(b""), ByteVec(), ByteVec(""):
        assert not vec


def test_bytevec_eq():
    vec = ByteVec(b"hello")
    assert vec == b"hello"
    assert vec == ByteVec(b"hello")
    assert vec != b"world"
    assert vec != ByteVec(b"world")


### test getitem and slice


@pytest.mark.parametrize("oob_read", [OOBReads.RETURN_ZERO, OOBReads.FAIL])
def test_bytevec_getitem(oob_read):
    vec = ByteVec(b"hello", oob_read=oob_read)
    assert vec[0] == ord("h")
    assert vec[1] == ord("e")
    assert vec[2] == ord("l")
    assert vec[3] == ord("l")
    assert vec[4] == ord("o")

    if oob_read == OOBReads.FAIL:
        with pytest.raises(IndexError):
            vec[5]
    else:
        assert vec[5] == 0


@pytest.mark.parametrize("oob_read", [OOBReads.RETURN_ZERO, OOBReads.FAIL])
def test_bytevec_getitem_negative(oob_read):
    vec = ByteVec(b"hello", oob_read=oob_read)
    assert vec[-1] == ord("o")
    assert vec[-2] == ord("l")
    assert vec[-3] == ord("l")
    assert vec[-4] == ord("e")
    assert vec[-5] == ord("h")

    if oob_read == OOBReads.FAIL:
        with pytest.raises(IndexError):
            vec[-6]
    else:
        assert vec[-6] == 0


def test_bytevec_slice_concrete():
    vec = ByteVec(b"hello")

    assert len(vec[1:1]) == 0

    vec_slice = vec[:3]
    assert len(vec_slice) == 3
    assert vec_slice == b"hel"

    vec_slice = vec[:]
    assert vec_slice is not vec
    assert len(vec_slice) == 5
    assert vec_slice == b"hello"
    assert vec_slice == vec

    vec_slice = vec[4:1]
    assert len(vec_slice) == 0


def test_bytevec_slice_symbolic():
    x = BitVec("x", 40)
    vec = ByteVec(x)

    assert len(vec[1:1]) == 0

    vec_slice = vec[:3]
    assert len(vec_slice) == 3
    assert vec_slice._data == [Extract(39, 16, x)]


def test_bytevec_slice_mixed():
    x = BitVec("x", 16)
    vec = ByteVec([b"hello", x, b"world"])

    tests = [
        (vec[:3], b"hel"),
        (vec[5:7], ByteVec(x)),
        (vec[8:], b"orld"),
        (vec[3:9], ByteVec([b"lo", x, b"wo"])),
        (vec[100:120], ByteVec()),
    ]

    for actual, expected in tests:
        print(f"actual={actual}, expected={expected}")
        assert actual == expected
        assert actual._well_formed()


def test_bytevec_assign_slice():
    with pytest.raises(HalmosException):
        vec = ByteVec(b"hello")
        vec[:3] = b"123"
