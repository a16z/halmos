# SPDX-License-Identifier: AGPL-3.0
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, ForwardRef

from sortedcontainers import SortedDict
from z3 import BitVecRef, If, eq, is_bool, is_bv, is_bv_value, simplify, substitute

from .logs import warn
from .utils import (
    Byte,
    Word,
    bv_value_to_bytes,
    byte_length,
    con,
    concat,
    extract_bytes,
    try_bv_value_to_bytes,
    unbox_int,
)

UnwrappedBytes = bytes | Byte
WrappedBytes = ForwardRef("Chunk") | ForwardRef("ByteVec")
Bytes = UnwrappedBytes | WrappedBytes


def try_concat(lhs: Any, rhs: Any) -> Any | None:
    """Attempt to concatenate two values together if they have the same type"""
    if isinstance(lhs, bytes) and isinstance(rhs, bytes):
        return lhs + rhs

    return None


def defrag(data: list) -> list:
    """Merge adjacent bytes into a single element"""

    if len(data) <= 1:
        return data

    output = []

    # accumulator, used to merge adjacent elements of the same type
    acc = None

    for elem in data:
        if acc is None:
            acc = elem
            continue

        concatenated = try_concat(acc, elem)
        if concatenated is not None:
            acc = concatenated
            continue

        output.append(acc)
        acc = elem

    # make sure the last element has been flushed
    if acc is not None:
        output.append(acc)

    return output


class Chunk(ABC):
    _empty = None

    def __init__(self, data, start, length) -> None:
        self.data = data

        # a start offset into the data
        self.start = start

        # the length of the chunk (may be less than the length of the data itself)
        self.length = length

    @staticmethod
    def wrap(data: UnwrappedBytes) -> "Chunk":
        """
        Wrap a value in a Chunk object to represent a span of bytes.

        This is a factory method that returns either a ConcreteChunk or a SymbolicChunk.

        Supported data types:
        - int: a single byte, resulting in a ConcreteChunk of length 1 (raises if value does not fit in a byte)
        - bytes: a sequence of bytes, resulting in a ConcreteChunk of the same length (empty bytes are supported)
        - BitVecRef: if it is a bitvec value, it is converted to bytes and wrapped in a ConcreteChunk.
            Otherwise, it is wrapped in a SymbolicChunk of the same length.
        """

        # convert bv values to bytes if possible
        if is_bv_value(data):
            data = bv_value_to_bytes(data)

        if isinstance(data, int):
            # assume a single byte, raises if value does not fit in a byte
            data = int.to_bytes(data, 1, "big")

        if isinstance(data, bytes):
            return ConcreteChunk(data)
        elif isinstance(data, BitVecRef):
            return SymbolicChunk(data)
        else:
            raise TypeError(f"Unsupported data type: {type(data)}")

    @staticmethod
    def empty() -> "Chunk":
        """A convenient way to get an empty chunk.

        In order to test for emptiness, instead of comparing to Chunk.empty(), it may be better to use:
        - `if not chunk` or
        - `if len(chunk) == 0`
        """
        if Chunk._empty is None:
            Chunk._empty = ConcreteChunk(b"")
        return Chunk._empty

    def __iter__(self):
        raise TypeError("Chunk object is not iterable")

    def __getitem__(self, key) -> Byte | ForwardRef("Chunk"):
        if isinstance(key, slice):
            start = key.start or 0
            stop = key.stop if key.stop is not None else self.length
            step = key.step or 1

            if step != 1:
                raise NotImplementedError(f"slice with step={step} not supported")

            # TODO: should we return an empty chunk or raise if start >= stop?
            # if start >= stop or start >= self.length:
            #     return Chunk.empty()

            if not (0 <= start <= self.length) or not (0 <= stop <= self.length):
                raise IndexError(key)

            return self.slice(start, stop)

        return self.get_byte(key)

    def __len__(self) -> int:
        return self.length

    def concretize(self, substitution: dict[BitVecRef, BitVecRef]) -> "Chunk":
        """
        Replace all symbols in the data with their corresponding concrete values,
        if they exist in the given substitution mapping.

        Return a new object with concrete values, or self if no substitution is made.
        """

        if not isinstance(self, SymbolicChunk):
            return self

        data = self.data
        # TODO: call substitute() only when the data contains variables to be substituted
        new_data = substitute(data, *substitution.items())

        # NOTE: `new_data is data` doesn't work, because substitute() always returns a new object even if no substitution is made
        if eq(new_data, data):
            return self

        new_data = simplify(new_data)

        return (
            ConcreteChunk(bv_value_to_bytes(new_data), self.start, self.length)
            if is_bv_value(new_data)
            else SymbolicChunk(new_data, self.start, self.length)
        )

    @abstractmethod
    def get_byte(self, offset) -> Byte:
        raise NotImplementedError

    @abstractmethod
    def slice(self, start, stop) -> "Chunk":
        raise NotImplementedError

    @abstractmethod
    def unwrap(self) -> UnwrappedBytes:
        raise NotImplementedError


class ConcreteChunk(Chunk):
    """A chunk of concrete, native bytes"""

    def __init__(self, data: bytes, start=0, length=None):
        self.data_byte_length = len(data)

        if length is None:
            length = self.data_byte_length - start

        assert start >= 0
        assert length >= 0
        assert start + length <= self.data_byte_length

        super().__init__(data, start, length)

    def get_byte(self, offset) -> int:
        """
        Return a single byte at the given offset (fast given that this is a native operation)

        Complexity: O(1)
        """

        if not (0 <= offset < self.length):
            raise IndexError(offset)

        return self.data[self.start + offset]

    def slice(self, start, stop) -> "ConcreteChunk":
        """
        Return a slice of the chunk, as a new chunk (this is fast and does not copy the backing data)

        Complexity: O(1)
        """

        return ConcreteChunk(self.data, self.start + start, stop - start)

    def unwrap(self) -> bytes:
        """
        Return the data as a single value, this is where the actual slicing/copying is done

        Complexity: O(n)
        """

        # if this chunk represents the entire data, return the data itself
        if self.length == self.data_byte_length:
            return self.data

        return self.data[self.start : self.start + self.length]

    def __eq__(self, other) -> bool:
        # allow comparison of empty symbolic and concrete chunks
        if isinstance(other, Chunk) and not self and not other:
            return True

        if not isinstance(other, ConcreteChunk):
            return False

        # unwrap() may create copies of the underlying data
        # could be improved to scan only once, with O(1) space, if this becomes a bottleneck
        return self.length == len(other) and self.unwrap() == other.unwrap()

    def __repr__(self) -> str:
        return f"ConcreteChunk({self.data.hex()}, start={self.start}, length={self.length})"


class SymbolicChunk(Chunk):
    """A chunk of symbolic bytes"""

    def __init__(self, data: BitVecRef, start=0, length=None):
        self.data_byte_length = byte_length(data)

        if length is None:
            length = self.data_byte_length - start

        assert start >= 0
        assert length >= 0
        assert start + length <= self.data_byte_length

        super().__init__(data, start, length)

    def get_byte(self, offset) -> BitVecRef:
        """
        Return a single byte at the given offset.

        This can be slow because it involves an Extract expression on a potentially large BitVec.

        Complexity: O(n)?
        """

        if not (0 <= offset < self.length):
            raise IndexError(offset)

        return extract_bytes(self.data, self.start + offset, 1)

    def slice(self, start, stop) -> "SymbolicChunk":
        """
        Return a slice of the chunk, as a new chunk (this is fast and does not copy the backing data)

        Complexity: O(1)
        """

        return SymbolicChunk(self.data, self.start + start, stop - start)

    def unwrap(self) -> BitVecRef:
        """
        Return the data as a single value, this is where the actual slicing/copying is done

        This can be slow because it involves an Extract expression on a potentially large BitVec.

        Complexity: O(n)?
        """

        # if this chunk represents the entire data, return the data itself
        if self.length == self.data_byte_length:
            return self.data

        return extract_bytes(self.data, self.start, self.length)

    def __eq__(self, other) -> bool:
        if isinstance(other, Chunk) and not self and not other:
            return True

        if not isinstance(other, SymbolicChunk):
            return False

        return self.length == len(other) and eq(self.unwrap(), other.unwrap())

    def __repr__(self) -> str:
        return f"SymbolicChunk({self.data!r}, start={self.start}, length={self.length})"


@dataclass
class ChunkInfo:
    """Metadata about a chunk at a given offset in a ByteVec."""

    index: int  # -1 if not found
    chunk: Chunk | None = None
    start: int | None = None
    end: int | None = None  # end offset, i.e. start + len(chunk)

    def found(self) -> bool:
        return self.index >= 0


class ByteVec:
    """
    ByteVec represents a sequence of mixed concrete/symbolic chunks of bytes.

    Supported operations:
    - append: add a new chunk to the end of the ByteVec
    - get a single byte at a given offset
    - get a slice (returns a ByteVec)
    - get the length of the ByteVec

    - assign a byte
    - assign a slice

    - compare equality with another ByteVec
    - unwrap (returns the entire ByteVec as a single value, either bytes or a BitVecRef)
    """

    def __init__(
        self,
        data: Chunk | None = None,
        _chunks: SortedDict | None = None,
        _length: int | None = None,
    ):
        self.chunks = _chunks if _chunks is not None else SortedDict()
        self.length = _length or 0

        # for convenience, allow passing a single chunk directly
        if data is not None:
            assert not self.chunks
            if isinstance(data, list | tuple):
                for chunk in data:
                    self.append(chunk)
            else:
                self.append(data)

    def __len__(self) -> int:
        return self.length

    def __repr__(self) -> str:
        return f"ByteVec({self.chunks!r})"

    def __eq__(self, other) -> bool:
        if not isinstance(other, ByteVec):
            warn(
                f"can't directly compare ByteVec with {type(other)}, did you mean to wrap it in a ByteVec?"
            )
            return False

        if len(self) != len(other):
            return False

        # can be expensive, but we can't compare chunks one by one
        self_unwrapped = self.unwrap()
        other_unwrapped = other.unwrap()

        if is_bv(self_unwrapped):
            self_unwrapped = try_bv_value_to_bytes(simplify(self_unwrapped))

        if is_bv(other_unwrapped):
            other_unwrapped = try_bv_value_to_bytes(simplify(other_unwrapped))

        if is_bv(self_unwrapped) and is_bv(other_unwrapped):
            return eq(self_unwrapped, other_unwrapped)

        if isinstance(self_unwrapped, bytes) and isinstance(other_unwrapped, bytes):
            return self_unwrapped == other_unwrapped

        return False

    def __iter__(self):
        raise TypeError("ByteVec object is not iterable")

    ### internal methods

    def _dump(self, msg=None):
        print(f"-- MEMDUMP (length: {self.length}) -- {msg if msg else ''}")
        for start, chunk in self.chunks.items():
            print(f"chunk@{start}: {chunk}")

    def _well_formed(self, msg=None) -> bool:
        self._dump(msg=msg)
        cumulative_length = 0
        for start, chunk in self.chunks.items():
            if len(chunk) == 0:
                raise ValueError("Empty chunk")
            if start != cumulative_length:
                raise ValueError("Non-contiguous chunks")
            cumulative_length += len(chunk)

        if cumulative_length != self.length:
            raise ValueError("Length mismatch")

        return True

    def _num_chunks(self) -> int:
        return len(self.chunks)

    def _load_chunk(self, offset) -> ChunkInfo:
        """
        Locate the chunk that contains the given offset.

        Complexity: O(log n) where n is the number of chunks (thanks to the backing SortedDict)
        """

        if offset < 0:
            raise IndexError(offset)

        if offset >= self.length:
            return ChunkInfo(index=-1)

        index = self.chunks.bisect_right(offset) - 1
        start, chunk = self.chunks.peekitem(index)
        return ChunkInfo(index=index, chunk=chunk, start=start, end=start + len(chunk))

    ### write operations

    def __set_chunk(self, start_offset: int, chunk: Chunk) -> bool:
        """
        Set a chunk at the given offset.

        Internal usage only, does not update length or check for overlaps.

        Returns True if the chunk was set
        """

        # ignore empty chunks
        if not chunk:
            return False

        self.chunks[start_offset] = chunk
        return True

    def append(self, chunk: Bytes) -> None:
        """
        Append a new chunk at the end of the ByteVec.

        This does not copy the data, it just adds a reference to it.

        Complexity: O(1)
        """

        if isinstance(chunk, ByteVec):
            # unwrap the ByteVec into chunks and store them
            for inner_chunk in chunk.chunks.values():
                self.append(inner_chunk)
            return

        # if the data is not wrapped, try to wrap it
        if not isinstance(chunk, Chunk):
            chunk = Chunk.wrap(chunk)

        start = self.length
        if self.__set_chunk(start, chunk):
            self.length += len(chunk)

    def set_byte(self, offset: int, value: Byte) -> None:
        byte_chunk = Chunk.wrap(value)

        # value must be a byte
        assert len(byte_chunk) == 1

        if offset >= self.length:
            # we are past the end of the ByteVec, so we must backfill
            self.append(b"\x00" * (offset - self.length))
            self.append(byte_chunk)
            return

        chunk_info = self._load_chunk(offset)
        assert chunk_info.found()

        chunk = chunk_info.chunk
        offset_in_chunk = offset - chunk_info.start
        assert 0 <= offset_in_chunk < len(chunk)

        # we are overwriting a byte in an existing chunk
        # let's keep the existing chunk data and create new chunks for the parts
        # before and after the byte (pointing at the existing data, but with
        # different start offsets and lengths)
        #
        #                         start=offset
        #                         length=1
        #                         data=b
        # ┌──────────────────────┐┌───┐┌───────────────────────┐
        # │      pre_chunk       ││ b ││      post_chunk       │
        # └──────────────────────┘└───┘└───────────────────────┘
        # │                      │     │                       │
        #   start=<unchanged>            start=offset + 1
        # │ end=offset           │     │ end=<unchanged>       │
        #   data=old_chunk_data          data=old_chunk_data
        # │                      │     │                       │
        # ┌────────────────────────────────────────────────────┐
        # │                  old_chunk_data                    │
        # └────────────────────────────────────────────────────┘

        pre_chunk = chunk[:offset_in_chunk]
        self.__set_chunk(chunk_info.start, pre_chunk)

        self.chunks[offset] = Chunk.wrap(value)

        post_chunk = chunk[offset_in_chunk + 1 :]
        self.__set_chunk(offset + 1, post_chunk)

    def set_slice(self, start: int, stop: int, value: Bytes) -> None:
        """
        Assign a byte range value to the ByteVec between offsets start (inclusive) and stop (exclusive).

        Supported value types:
        - bytes: a sequence of bytes
        - BitVecRef: a symbolic value
        - Chunk: a concrete or symbolic chunk
        - ByteVec: a sequence of chunks (e.g. from reading an existing slice)

        Raises if the value is not the same length as the slice.
        """
        if start == stop:
            return

        if start > stop:
            raise ValueError("Start index must be less than or equal to stop index")

        if start < 0 or stop < 0:
            raise IndexError

        if isinstance(value, bytes) or is_bv(value):
            value = Chunk.wrap(value)

        if stop - start != len(value):
            raise ValueError("Length of value must match the length of the slice")

        if start >= self.length:
            # we are past the end of the ByteVec, so we must backfill
            self.append(b"\x00" * (start - self.length))
            self.append(value)
            return

        # there has to be a first chunk because of the start >= self.length check
        first_chunk = self._load_chunk(start)
        assert first_chunk.found()

        # aligned write, just overwrite the existing chunk
        # length is unchanged, so we can return early
        if start == first_chunk.start and stop == first_chunk.end:
            self.__set_chunk(first_chunk.start, value)
            return

        # chunk that has the last byte of the slice,
        # or not found if stop >= self.length
        last_chunk = self._load_chunk(stop - 1)

        # remove the chunks that will be overwritten
        remove_from = first_chunk.index + 1
        remove_to = None if stop >= self.length else last_chunk.index + 1
        for key in self.chunks.keys()[remove_from:remove_to]:
            del self.chunks[key]

        # truncate the first_chunk
        pre_chunk = first_chunk.chunk[: start - first_chunk.start]
        self.__set_chunk(first_chunk.start, pre_chunk)

        if isinstance(value, ByteVec):
            # unpack the ByteVec into chunks and store them
            for inner_chunk_start, inner_chunk in value.chunks.items():
                self.__set_chunk(start + inner_chunk_start, inner_chunk)
        else:
            # store the value as a single chunk
            self.__set_chunk(start, value)

        # truncate the last chunk
        if last_chunk.end and stop < last_chunk.end:
            post_chunk = last_chunk.chunk[stop - last_chunk.start :]
            self.__set_chunk(stop, post_chunk)

        self.length = max(self.length, stop)

    def __setitem__(self, key, value) -> None:
        if isinstance(key, slice):
            start = key.start or 0
            stop = key.stop or self.length
            step = key.step or 1

            if step != 1:
                raise NotImplementedError

            return self.set_slice(start, stop, value)

        return self.set_byte(key, value)

    def set_word(self, offset: int, value: Word) -> None:
        """
        Write a 32-byte word at the given offset.

        This is a thin wrapper that wraps the value as a Chunk and stores it.

        Supported types:
        - int: will be converted to 32 byte Chunk
        - BitVecRef: must be 32 bytes
        - bytes: must be 32 bytes
        - bool: will be converted to 32 byte SymbolicChunk
        """

        # convert to concrete value when possible
        if is_bv_value(value):
            value = value.as_long()

        if isinstance(value, int):
            value = int.to_bytes(value, 32, "big")
        elif is_bool(value):
            value = If(value, con(1), con(0))

        self.set_slice(offset, offset + 32, value)

    def concretize(self, substitution: dict[BitVecRef, BitVecRef]) -> "ByteVec":
        """
        Replace all symbols in the chunks with their corresponding concrete values,
        if they exist in the given substitution mapping.

        Return a new ByteVec object even if no substitution is made.
        """

        result = ByteVec()

        for chunk in self.chunks.values():
            result.append(chunk.concretize(substitution))

        return result

    ### read operations

    def slice(self, start: int, stop: int) -> "ByteVec":
        """
        Return a slice of data between offsets start (inclusive) and stop (exclusive).

        If some portion of [start:stop] is out of bounds, it will be filled with zeroes.

        Complexity:
        - O(log(num_chunks)) to locate the first chunk
        - plus complexity to iterate over the subsequent chunks (O(stop - start))
        - plus complexity to slice the first and last chunks (O(1) on concrete bytes, O(n) on symbolic bytes)
        - plus complexity to append the resulting chunks to a new ByteVec (O(stop - start))
        """

        result = ByteVec()

        expected_length = stop - start
        if expected_length <= 0:
            return result

        first_chunk = self._load_chunk(start)
        if not first_chunk.found():
            result.append(self.__read_oob(expected_length))
            return result

        for chunk_start, chunk in self.chunks.items()[first_chunk.index :]:
            if chunk_start >= stop:
                # we are past the end of the requested slice
                break

            if start <= chunk_start and chunk_start + len(chunk) <= stop:
                # the entire chunk is in the slice
                result.append(chunk)

            else:
                # a portion of the chunk is in the slice
                start_offset = max(0, start - chunk_start)
                end_offset = min(len(chunk), stop - chunk_start)

                assert end_offset - start_offset > 0

                chunk_slice = chunk[start_offset:end_offset]
                result.append(chunk_slice)

        num_missing_bytes = expected_length - len(result)
        if num_missing_bytes:
            result.append(self.__read_oob(num_missing_bytes))

        assert len(result) == expected_length
        return result

    def get_byte(self, offset: int) -> Byte:
        """
        Return a single byte at the given offset.

        If the offset is out of bounds, returns 0.

        Complexity:
        - O(log(num_chunks)) to locate the chunk
        - plus the complexity to extract a byte (O(1) on concrete chunks, O(num_bytes) on symbolic chunks)
        """

        chunk = self._load_chunk(offset)
        if not chunk.found():
            return self.__read_oob_byte()

        return chunk.chunk.get_byte(offset - chunk.start)

    def get_word(self, offset) -> Word:
        """
        Return a single word (32 bytes) at the given offset.

        This is a thin wrapper that just loads a slice and converts it to a single value (int or bv) rather than bytes.

        If some portion of [offset:offset+32] is out of bounds, returns zeroes.
        """

        data = self.slice(offset, offset + 32).unwrap()
        return unbox_int(data)

    def __getitem__(self, key) -> Byte | ForwardRef("ByteVec"):
        if isinstance(key, slice):
            start = key.start or 0
            stop = key.stop if key.stop is not None else self.length
            step = key.step or 1

            if step != 1:
                raise NotImplementedError(f"slice with step={step} not supported")

            return self.slice(start, stop)

        return self.get_byte(key)

    def __read_oob(self, num_bytes) -> Chunk:
        return Chunk.wrap(b"\x00" * num_bytes)

    def __read_oob_byte(self) -> int:
        return 0

    def unwrap(self) -> UnwrappedBytes:
        """
        Return the entire ByteVec as a single value.

        This is where the actual slicing/copying is done.

        Complexity: O(n)
        """

        if not self:
            return b""

        # unwrap and defrag, ideally this becomes either a single bytes or a single BitVecRef
        data = [chunk.unwrap() for chunk in self.chunks.values()]
        data = [try_bv_value_to_bytes(chunk) for chunk in data]
        data = defrag(data)

        if len(data) == 1:
            item = data[0]
            return simplify(item) if is_bv(item) else item

        # if we have multiple chunks, concatenate them
        result = simplify(concat(data))
        return result

    def copy(self):
        """
        Return a shallow copy of the ByteVec:
        - copies the container for the chunks
        - does not copy the chunks themselves, which are immutable
        """

        return ByteVec(
            _chunks=self.chunks.copy(),
            _length=self.length,
        )
