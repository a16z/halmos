import pytest

from z3 import BitVec, BitVecVal, Extract

from halmos.bytevec import *
from halmos.exceptions import HalmosException
from halmos.utils import concat

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


### chunk tests


def test_empty_chunk():
    chunk = Chunk.empty()

    # empty chunk is falsy
    assert not chunk
    assert len(chunk) == 0

    # empty chunk is a singleton
    assert chunk is Chunk.empty()

    # equality comparison works as expected
    assert chunk == Chunk.wrap(b"")

    # a slice with start == stop is empty
    assert chunk == Chunk.wrap(b"abc").slice(2, 2)

    # can't access bytes of the empty chunk
    with pytest.raises(IndexError):
        chunk[0]


def test_concrete_chunk():
    chunk = Chunk.wrap(b"hello")
    assert len(chunk) == 5
    assert chunk  # non empty chunk is truthy
    assert chunk.unwrap() == b"hello"
    assert chunk[0] == b"h"[0]
    assert chunk[1] == b"e"[0]
    assert chunk[2] == b"l"[0]
    assert chunk[3] == b"l"[0]
    assert chunk[4] == b"o"[0]

    with pytest.raises(IndexError):
        chunk[-1]

    with pytest.raises(IndexError):
        chunk[5]

    assert chunk[2:4].unwrap() == b"ll"
    assert chunk[:].unwrap() == b"hello"
    assert chunk[2:2] == Chunk.empty()
    assert Chunk.empty() == chunk[2:2]
    assert not chunk[1:1]

    other_chunk = Chunk.wrap(b"hello world")
    other_chunk_slice = other_chunk[:5]
    assert chunk != other_chunk

    # can be compared directly without unwrapping
    assert chunk == other_chunk_slice

    # equality is reflexive
    assert chunk == chunk

    # equality is symmetric
    assert other_chunk_slice == chunk

    # can't assign to a chunk
    with pytest.raises(TypeError):
        chunk[0] = 42

    with pytest.raises(TypeError):
        chunk[0:2] = b"bb"

    # wrapping a bv value yields a concrete chunk
    bv = BitVecVal(0x1234, 16)
    bv_chunk = Chunk.wrap(bv)
    assert len(bv_chunk) == 2
    assert bv_chunk.unwrap() == b"\x12\x34"


def test_symbolic_chunk():
    x = BitVec("x", 16)
    chunk = Chunk.wrap(x)
    assert len(chunk) == 2
    assert eq(chunk[0], extract_bytes(x, 0, 1))
    assert eq(chunk[1], extract_bytes(x, 1, 1))
    assert chunk[1:1] == Chunk.empty()
    assert Chunk.empty() == chunk[1:1]
    assert not chunk[1:1]
    assert eq(chunk[:].unwrap(), x)

    with pytest.raises(IndexError):
        chunk[-1]

    with pytest.raises(IndexError):
        chunk[2]

    # can't assign to a chunk
    with pytest.raises(TypeError):
        chunk[0] = BitVec("y", 8)

    with pytest.raises(TypeError):
        chunk[0:2] = BitVec("y", 16)

    # equality is reflexive
    assert chunk == chunk

    # equality is symmetric
    assert chunk == Chunk.wrap(x)
    assert Chunk.wrap(x) == chunk

    assert chunk != Chunk.wrap(BitVec("y", 16))


### test bytevec constructor


def test_bytevec_constructor_nodata():
    vec = ByteVec()
    assert vec._well_formed()
    assert len(vec) == 0
    assert not vec
    assert vec._num_chunks() == 0


def test_bytevec_constructor_bytes():
    vec = ByteVec(b"hello")
    assert vec._well_formed()
    assert len(vec) == 5
    assert vec._num_chunks() == 1


def test_bytevec_constructor_bitvecvalue():
    # when we use a concrete bitvecval
    vec = ByteVec(BitVecVal(0x1234, 16))
    assert vec._well_formed()
    assert len(vec) == 2
    assert vec._num_chunks() == 1

    # then the bitvecval has been converted to bytes
    assert vec.unwrap() == b"\x12\x34"


def test_bytevec_constructor_bitvec():
    # when we use a symbolic bitvec
    x = BitVec("x", 16)
    vec = ByteVec(x)
    assert vec._well_formed()
    assert len(vec) == 2

    # then the bitvec is stored as-is
    assert eq(vec.unwrap(), x)


def test_bytevec_constructor_concat():
    # when we use a mixed concat expression
    x = BitVec("x", 16)
    expr = concat([BitVecVal(0, 16), x])
    vec = ByteVec(expr)
    assert vec._well_formed()
    assert len(vec) == 4

    # then the concat expression has been unwrapped
    assert vec.unwrap() == expr


def test_bytevec_constructor_hexstr():
    data = bytes.fromhex("deadbeef")
    vec = ByteVec(data)
    assert vec._well_formed()
    assert len(vec) == 4
    assert vec.unwrap() == data


### test bytevec behavior


def test_bytevec_append_multiple():
    vec = ByteVec()
    vec.append(b"hello")
    vec.append(BitVecVal(0x1234, 16))
    assert vec._well_formed()
    assert len(vec) == 7

    # we expect the output to be lowered to bytes and defragged
    assert vec.unwrap() == b"hello\x12\x34"


def test_bytevec_empty_should_be_falsy():
    for vec in ByteVec(b""), ByteVec(), ByteVec(Chunk.empty()):
        assert not vec


def test_bytevec_eq():
    vec = ByteVec(b"hello")

    # eq is reflexive
    assert vec == vec

    # eq is symmetric
    assert vec == ByteVec(b"hello")
    assert ByteVec(b"hello") == vec

    # supports != operator
    assert vec != b"world"
    assert vec != ByteVec(b"world")

    # fragmentation doesn't affect equality
    fragmented = ByteVec()
    fragmented.append(b"hel")
    fragmented.append(b"")
    fragmented.append(Chunk.wrap(b"lol")[:2])
    assert vec == fragmented


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
    with pytest.raises(IndexError):
        vec[-1]


def assert_empty(bytevec):
    """Checks the canonical ways to test for an empty bytevec."""

    # 1000000 loops, best of 5: 0.055 usec per loop -- best
    assert not bytevec

    # 1000000 loops, best of 5: 0.073 usec per loop
    assert len(bytevec) == 0

    # 1000000 loops, best of 5: 0.101 usec per loop
    assert bytevec.unwrap() == b""

    # 1000000 loops, best of 5: 4.069 usec per loop -- worst
    assert bytevec == ByteVec()


def test_bytevec_slice_concrete():
    vec = ByteVec(b"hello")

    # empty slice
    assert_empty(vec[1:1])
    assert_empty(vec[4:1])
    assert_empty(vec[5:])
    assert_empty(vec[:0])

    vec_slice = vec[:3]
    assert len(vec_slice) == 3
    assert vec_slice.unwrap() == b"hel"

    vec_slice = vec[:]

    # TODO: if immutable, should return the same object
    # assert vec_slice is vec

    assert len(vec_slice) == 5
    assert vec_slice.unwrap() == b"hello"
    assert vec_slice == vec


def test_bytevec_slice_symbolic():
    x = BitVec("x", 40)
    vec = ByteVec(x)

    # empty slice
    assert_empty(vec[1:1])
    assert_empty(vec[4:1])
    assert_empty(vec[5:])
    assert_empty(vec[:0])

    # slice from beginning
    vec_slice = vec[:3]
    assert len(vec_slice) == 3
    assert eq(vec_slice.unwrap(), Extract(39, 16, x))


def test_bytevec_slice_mixed():
    x = BitVec("x", 16)
    vec = ByteVec([b"hello", x, b"world"])

    tests = [
        (vec[:3], ByteVec(b"hel")),
        (vec[3:3], ByteVec()),
        (vec[5:7], ByteVec(x)),
        (vec[8:], ByteVec(b"orld")),
        (vec[3:9], ByteVec([b"lo", x, b"wo"])),
        (vec[7:16], ByteVec(b"world\x00\x00\x00\x00")),
        (vec[100:120], ByteVec(bytes.fromhex("00" * 20))),
    ]

    for actual, expected in tests:
        assert actual == expected
        assert actual._well_formed()

        # TODO: separate immutable type?
        # can not assign to the slice
        # with pytest.raises(TypeError):
        #     actual[0] = 42


# TODO: separate immutable type?
# def test_bytevec_assign_slice():
#     with pytest.raises(TypeError):
#         vec = ByteVec(b"hello")
#         vec[:3] = b"123"
