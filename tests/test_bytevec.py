import pytest

from z3 import BitVec, BitVecVal

from halmos.bytevec import ByteVec, concat


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
    assert vec._data == [b"hello", b"\x12\x34"]
    assert vec._well_formed()


def test_bytevec_empty_should_be_falsy():
    for vec in ByteVec(b""), ByteVec(), ByteVec(""):
        assert not vec


def test_bytevec_getitem():
    vec = ByteVec(b"hello")
    assert vec[0] == ord("h")
    assert vec[1] == ord("e")
    assert vec[2] == ord("l")
    assert vec[3] == ord("l")
    assert vec[4] == ord("o")
    assert vec[5] == None


def test_bytevec_getitem_negative():
    vec = ByteVec(b"hello")
    assert vec[-1] == ord("o")
    assert vec[-2] == ord("l")
    assert vec[-3] == ord("l")
    assert vec[-4] == ord("e")
    assert vec[-5] == ord("h")
    assert vec[-6] == None


def test_bytevec_slice_concrete():
    vec = ByteVec(b"hello")

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
    vec = ByteVec(BitVec("x", 40))

    vec_slice = vec[:3]
    assert len(vec_slice) == 3
    assert vec_slice._data == [vec[0], vec[1], vec[2]]
