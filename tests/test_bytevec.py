import pytest
from z3 import BitVec, BitVecVal, Concat, Extract, eq

from halmos.bytevec import ByteVec, Chunk, defrag
from halmos.utils import concat, extract_bytes


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
    mixed = [b"hello", BitVecVal(int.from_bytes(b"world", "big"), 30), b"!"]
    assert defrag(mixed) == mixed

    x, y, z = (BitVec(_, 8) for _ in "xyz")
    assert defrag([x]) == [x]
    assert defrag([x, y]) == [x, y]
    assert defrag([x, y, z]) == [x, y, z]


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


def test_bytevec_getitem():
    vec = ByteVec(b"hello")
    assert vec[0] == ord("h")
    assert vec[1] == ord("e")
    assert vec[2] == ord("l")
    assert vec[3] == ord("l")
    assert vec[4] == ord("o")
    assert vec[5] == 0


def test_bytevec_getitem_negative():
    vec = ByteVec(b"hello")
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


# ┌───┐
# │new│
# └───┘
# ┌───┐         ┌───┐
# │ . │ ──────▶ │new│
# └───┘         └───┘
def test_memory_write_byte_stomping_1_concrete_byte(mem):
    # when we have a 1 byte chunk
    mem[0] = 0x42

    # and overwrite it with another 1 byte chunk
    mem[0] = 0x43

    # then the existing chunk should be overwritten
    assert mem._well_formed()
    assert len(mem) == 1
    assert mem[0] == 0x43


# ┌───┐
# │new│
# └───┘
# ┌───┬───┐         ┌───┬───┐
# │ . │ . │ ──────▶ │new│ . │
# └───┴───┘         └───┴───┘
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


#     ┌───┐
#     │new│
#     └───┘
# ┌───┬───┐         ┌───┬───┐
# │ . │ . │ ──────▶ │ . │new│
# └───┴───┘         └───┴───┘
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


#     ┌───┐
#     │new│
#     └───┘
# ┌───┬───┬───┐          ┌───┬───┬───┐
# │ . │ . │ . │  ──────▶ │ . │new│ . │
# └───┴───┴───┘          └───┴───┴───┘
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


def test_memory_write_byte_non_zero_start():
    # setup memory with multiple chunks
    mem = ByteVec()
    mem.append(b"\x01\x02\x03")
    mem.append(b"\x04\x05\x06")

    # when we write in the second chunk (i.e. non zero start offset)
    mem[4] = 0x42

    # then the existing chunk should be split
    assert mem._well_formed()
    assert len(mem) == 6
    assert mem[3] == 0x04
    assert mem[4] == 0x42
    assert mem[5] == 0x06


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
def test_memory_write_slice_over_single_chunk(mem):
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
def test_memory_write_slice_over_multiple_chunks(mem):
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
def test_memory_write_slice_across_prechunk_extend_concrete(mem):
    mem[:32] = b"hellohellohellohellohellohellohe"

    # stomp in the middle of the existing chunk and extend the memory
    mem[16:48] = b"worldworldworldworldworldworldwo"
    assert mem._well_formed()
    assert len(mem) == 48
    assert mem[:32].unwrap() == b"hellohellohellohworldworldworldw"


#       ┌───────────────┐
#       │///new chunk///│
#       └───────────────┘
# ┌─────────────┬─────────────┐         ┌─────┬───────────────┬──────┐
# │..old chunk..│..old chunk..│ ──────▶ │..old│///new chunk///│hunk..│
# └─────────────┴─────────────┘         └─────┴───────────────┴──────┘
def test_memory_write_slice_across_prechunk_postchunk(mem):
    # setup
    mem[:5] = b"hello"
    mem[5:10] = b"world"

    # write the new chunk across the existing chunks
    mem[3:7] = b"!!!!"

    assert mem._well_formed()
    assert len(mem) == 10
    assert mem[:].unwrap() == b"hel!!!!rld"


def test_memory_write_slice_across_prechunk_extend_mixed(mem):
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


def test_memory_write_slice_bytevec(mem):
    mem[:5] = b"hello"
    mem[5:10] = b"world"

    # mem[0:10] is a bytevec with 2 chunks
    mem[10:20] = mem[0:10]

    assert mem._well_formed()
    assert len(mem) == 20

    # unwrap() recursively calls unwrap() on all chunks and bytevecs
    assert mem[:].unwrap() == b"helloworldhelloworld"

    # mem[5:15] is a bytevec with 1 concrete chunk and a slice of a bytevec
    mem[40:50] = mem[5:15]
    assert mem._well_formed()
    assert len(mem) == 50
    assert mem[40:50].unwrap() == b"worldhello"

    # writing to mem[5:15] will delete the concrete chunk at 5 and split the bytevec at 10
    mem[5:15] = mem[30:40]
    assert mem._well_formed()
    assert len(mem) == 50
    assert mem[5:15].unwrap() == b"\x00" * 10


def test_appending_bytevec_to_bytevec_makes_copy(mem):
    # setup
    mem[:5] = b"hello"
    mem[5:10] = b"world"

    # grab a slice of memory (as a bytevec), write it back to memory
    hello_world_bytevec = mem[:10]

    # when append via a set_slice that happens to be at the end
    mem[10:20] = hello_world_bytevec

    # and we modify the bytevec
    hello_world_bytevec[:5] = b"bloop"

    # then the memory should not be affected
    assert mem[10:20].unwrap() == b"helloworld"

    # when we explicitly append
    hello_world_bytevec = mem[:10]
    mem.append(hello_world_bytevec)

    # and we modify the bytevec
    hello_world_bytevec[5:10] = b"bleep"

    # then memory should not be affected
    assert mem[20:30].unwrap() == b"helloworld"


def test_writing_bytevec_to_bytevec_makes_copy(mem):
    # setup
    mem[:5] = b"hello"
    mem[5:10] = b"world"

    other_bytevec = ByteVec(b"!!!!")

    # when we write the bytevec to memory
    mem[3:7] = other_bytevec

    # and we modify the bytevec
    other_bytevec[1:3] = b"$$"

    # then the memory should not be affected
    assert mem.unwrap() == b"hel!!!!rld"


def test_memory_write_slice_overlapping_forward(mem):
    mem[:5] = b"hello"

    # when we write a slice that overlaps with itself
    mem[2:7] = mem[:5]

    # then the existing memory should be correctly overwritten
    assert mem._well_formed()
    assert len(mem) == 7
    assert mem[:].unwrap() == b"hehello"


def test_memory_write_slice_overlapping_backward(mem):
    x = BitVec("x", 256)
    mem.set_word(32, x)

    # when we write a slice that overlaps with itself
    mem[16:48] = mem[32:64]

    # then the existing memory should be correctly overwritten
    assert mem._well_formed()
    assert len(mem) == 64

    # 16 bytes of zeroes, top half of x
    assert eq(mem[:32].unwrap(), Concat(BitVecVal(0, 128), Extract(255, 128, x)))

    # just x itself
    assert eq(mem[16:48].unwrap(), x)

    # bottom half of x, bottom half of x
    assert eq(mem[32:64].unwrap(), Concat(Extract(127, 0, x), Extract(127, 0, x)))
