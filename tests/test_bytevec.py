import pytest

from z3 import BitVec, BitVecVal, Extract

from halmos.bytevec import *
from halmos.exceptions import HalmosException
from halmos.utils import concat


@pytest.fixture
def mem():
    return ByteVec()


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


def test_memory_write_byte_basic(mem):
    # write a single byte into empty memory
    mem[0] = 0x42
    assert mem[0] == 0x42
    assert len(mem) == 1

    # write another byte to extend non-empty memory
    mem[12] = 0x42
    assert mem[12] == 0x42
    assert len(mem) == 13

    # write a single byte into an existing chunk
    mem[6] = 0x42
    assert len(mem) == 13  # unchanged
    assert mem[6] == 0x42


def test_memory_write_byte_splitting_1_concrete_byte(mem):
    # when we have a 1 byte chunk
    mem[0] = 0x42

    # and overwrite it with another 1 byte chunk
    mem[0] = 0x43

    # then the existing chunk should be overwritten
    assert mem._well_formed()
    assert len(mem) == 1
    assert mem[0] == 0x43


def test_memory_write_byte_splitting_2_concrete_bytes_no_prechunk():
    # when we have a 2 byte chunk
    mem = ByteVec(b"\x01\x02")

    # and overwrite it with a 1 byte chunk
    mem[0] = 0x42

    # then the existing chunk should be split
    assert mem._well_formed()
    assert len(mem) == 2

    # does a lookup in the single byte chunk at the beginning
    assert mem[0] == 0x42

    # does a lookup in ConcreteChunk(b'\\x01\\x02', start=1, length=1)
    assert mem[1] == 0x02


def test_memory_write_byte_splitting_2_concrete_bytes_no_postchunk():
    # when we have a 2 byte chunk
    mem = ByteVec(b"\x01\x02")

    # and overwrite it with a 1 byte chunk
    mem[1] = 0x42

    # then the existing chunk should be split
    assert mem._well_formed()
    assert len(mem) == 2

    # does a lookup in ConcreteChunk(b'\\x01\\x02', start=0, length=1)
    assert mem[0] == 0x01

    # does a lookup in the single byte chunk at the end
    assert mem[1] == 0x42


def test_memory_write_byte_splitting_3_concrete_bytes():
    # when we have a 3 byte chunk
    mem = ByteVec(b"\x01\x02\x03")

    # and overwrite it with a 1 byte chunk
    mem[1] = 0x42

    # then the existing chunk should be split
    assert mem._well_formed()
    assert len(mem) == 3

    # does a lookup in ConcreteChunk(b'\\x01\\x02\\x03', start=0, length=1)
    assert mem[0] == 0x01

    # does a lookup in the single byte chunk in the middle
    assert mem[1] == 0x42

    # does a lookup in ConcreteChunk(b'\\x01\\x02\\x03', start=2, length=1)
    assert mem[2] == 0x03


def test_memory_write_slice_empty(mem):
    mem[0:0] = b""
    assert_empty(mem)

    mem[42:42] = b""
    assert_empty(mem)


def test_memory_write_slice_length_mismatch(mem):
    with pytest.raises(ValueError):
        mem[0:1] = b"hello"

    mem[0] = 42
    with pytest.raises(ValueError):
        mem[:] = b"hello"

    with pytest.raises(ValueError):
        mem[0:32] = b"hello"


def test_memory_write_slice_into_empty_memory(mem):
    mem[2:7] = b"hello"
    assert mem._well_formed()
    assert len(mem) == 7
    assert mem[:].unwrap() == b"\x00\x00hello"


def test_memory_write_slice_past_existing_chunk(mem):
    mem.append(b"hello")
    mem[40:45] = b"world"
    assert mem._well_formed()
    assert len(mem) == 45
    assert mem[0:5].unwrap() == b"hello"
    assert mem[40:45].unwrap() == b"world"


# ┌──────────────────┐
# │////new chunk/////│
# └──────────────────┘
# ┌──────────────────┐           ┌──────────────────┐
# │....old chunk.....│  ──────▶  │////new chunk/////│
# └──────────────────┘           └──────────────────┘
def test_memory_write_slice_over_existing_chunk(mem):
    mem.append(BitVec("x", 40))
    mem[:] = b"world"
    assert mem._well_formed()
    assert len(mem) == 5
    assert mem[:].unwrap() == b"world"


# ┌───────────────────────┐
# │///////new chunk///////│
# └───────────────────────┘
# ┌───┬───┬───┬───┬───┬───┐         ┌───────────────────────┐
# │old│old│old│old│old│old│ ──────▶ │///////new chunk///////│
# └───┴───┴───┴───┴───┴───┘         └───────────────────────┘
def test_memory_write_slice_stomp_over_existing_chunks(mem):
    # setup some chunks
    mem[10:15] = b"world"
    assert mem._well_formed()
    assert len(mem) == 15
    assert mem[:].unwrap() == b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00world"

    mem[20:32] = b"foofeefoofum"
    assert mem._well_formed()
    assert len(mem) == 32
    assert (
        mem[:].unwrap()
        == b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00world\x00\x00\x00\x00\x00foofeefoofum"
    )

    # stomp the existing chunks, results in every chunk being overwritten
    #
    #    -- MEMDUMP (length: 32) -- after stomping
    #    chunk@0: ConcreteChunk(b'hellohellohellohellohellohellohe', start=0, length=32)

    mem[:32] = b"hellohellohellohellohellohellohe"
    assert mem._well_formed("after stomping")
    assert len(mem) == 32
    assert mem[:].unwrap() == b"hellohellohellohellohellohellohe"
    assert mem[:5].unwrap() == b"hello"


#     ┌───────────────┐
#     │///new chunk///│
#     └───────────────┘
# ┌───────────────────────┐         ┌───┬───────────────┬───┐
# │.......old chunk.......│ ──────▶ │...│///new chunk///│...│
# └───────────────────────┘         └───┴───────────────┴───┘
def test_memory_write_slice_into_existing_chunk(mem):
    # setup a chunk
    mem[2:7] = b"hello"
    assert len(mem) == 7

    # write into an existing chunk
    # results in the following layout:
    #
    #     -- MEMDUMP (length: 7) --
    #     chunk@0: ConcreteChunk(b'\x00\x00', start=0, length=2)
    #     chunk@2: ConcreteChunk(b'hello', start=0, length=2)
    #     chunk@4: ConcreteChunk(b'!!', start=0, length=2)
    #     chunk@6: ConcreteChunk(b'hello', start=4, length=1)

    mem[4:6] = b"!!"
    assert mem._well_formed()
    assert len(mem) == 7  # unchanged
    assert mem[:].unwrap() == b"\x00\x00he!!o"


#         ┌───────────────┐
#         │///new chunk///│
#         └───────────────┘
# ┌───────────────┐                 ┌──────┬───────────────┐
# │...old chunk...│         ──────▶ │...old│///new chunk///│
# └───────────────┘                 └──────┴───────────────┘
def test_memory_write_slice_across_existing_chunk_concrete(mem):
    mem[:32] = b"hellohellohellohellohellohellohe"

    # stomp in the middle of the existing chunk and extend the memory
    mem[16:48] = b"worldworldworldworldworldworldwo"
    assert mem._well_formed()
    assert len(mem) == 48
    assert mem[:32].unwrap() == b"hellohellohellohworldworldworldw"


def test_memory_write_slice_across_existing_chunk_mixed(mem):
    x = BitVec("x", 256)
    mem[:32] = x

    # stomp in the middle of the existing chunk and extend the memory
    woworld = b"worldworldworldworldworldworldwo"
    woworld_bv = BitVecVal(int.from_bytes(woworld[:16], "big"), 128)
    mem[16:48] = woworld
    assert mem._well_formed()
    assert len(mem) == 48
    assert eq(
        mem[:32].unwrap(), Concat(Extract(255, 128, x), BitVecVal(woworld_bv, 128))
    )
