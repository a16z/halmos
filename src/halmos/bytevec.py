# SPDX-License-Identifier: AGPL-3.0
from abc import ABC, abstractmethod
from enum import Enum
from typing import (
    Any,
    List,
    Optional,
    Tuple,
    Union as UnionType,
)

from sortedcontainers import SortedDict
from z3 import BitVecRef, Concat, is_bv, is_bv_value

from .exceptions import HalmosException
from .utils import (
    byte_length,
    bv_value_to_bytes,
    concat,
    eq,
    extract_bytes,
    is_bv_value,
)

Byte = UnionType[int, BitVecRef]
Bytes = UnionType["Chunk", "ByteVec"]


class OOBReads(Enum):
    """Enum to control the behavior of out-of-bounds reads in ByteVec"""

    RETURN_ZERO = 0
    FAIL = 1


def try_concat(lhs: Any, rhs: Any) -> Optional[Any]:
    """Attempt to concatenate two values together if they have the same type"""
    if isinstance(lhs, bytes) and isinstance(rhs, bytes):
        return lhs + rhs

    if is_bv(lhs) and is_bv(rhs):
        return Concat(lhs, rhs)

    return None


def defrag(data: List) -> List:
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
    def wrap(data: UnionType[bytes, BitVecRef]) -> "Chunk":
        # convert bv values to bytes if possible
        if is_bv_value(data):
            data = bv_value_to_bytes(data)

        if isinstance(data, bytes):
            return ConcreteChunk(data)
        elif isinstance(data, BitVecRef):
            return SymbolicChunk(data)
        else:
            raise TypeError(f"Unsupported data type: {type(data)}")

    @staticmethod
    def empty():
        """A convenient way to get an empty chunk.

        In order to test for emptiness, instead of comparing to Chunk.empty(), it may be better to use:
        - `if not chunk` or
        - `if len(chunk) == 0`
        """
        if Chunk._empty is None:
            Chunk._empty = ConcreteChunk(b"")
        return Chunk._empty

    def __getitem__(self, key):
        if isinstance(key, slice):
            start = key.start or 0
            stop = key.stop if key.stop is not None else self.length
            step = key.step or 1

            if step != 1:
                raise NotImplementedError(f"slice with step={step} not supported")

            if not (0 <= start < self.length) or not (0 <= stop <= self.length):
                raise IndexError(key)

            return self.slice(start, stop)

        return self.get_byte(key)

    def __len__(self):
        return self.length

    @abstractmethod
    def get_byte(self, offset):
        raise NotImplementedError

    @abstractmethod
    def slice(self, start, stop) -> "Chunk":
        raise NotImplementedError

    @abstractmethod
    def unwrap(self) -> UnionType[bytes, BitVecRef]:
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

    def __eq__(self, other):
        # allow comparison of empty symbolic and concrete chunks
        if isinstance(other, Chunk) and not self and not other:
            return True

        if not isinstance(other, ConcreteChunk):
            return False

        return self.length == len(other) and self.unwrap() == other.unwrap()

    def __repr__(self):
        return f"ConcreteChunk({self.data!r}, start={self.start}, length={self.length})"


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

    def __eq__(self, other):
        if isinstance(other, Chunk) and not self and not other:
            return True

        if not isinstance(other, SymbolicChunk):
            return False

        return self.length == len(other) and eq(self.unwrap(), other.unwrap())

    def __repr__(self):
        return f"SymbolicChunk({self.data!r})"


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
        data: Optional[Chunk] = None,
        oob_read: OOBReads = OOBReads.RETURN_ZERO,
    ):
        self.chunks = SortedDict()
        self.oob_read = oob_read
        self.length = 0

        # for convenience, allow passing a single chunk directly
        if data is not None:
            # if the data is not wrapped in a Chunk, try to wrap it
            if not isinstance(data, Chunk):
                data = Chunk.wrap(data)
            self.append(data)

    def __len__(self):
        return self.length

    def __repr__(self) -> str:
        return f"ByteVec({self.chunks!r})"

    def __eq__(self, other) -> bool:
        if not isinstance(other, ByteVec):
            return False

        if len(self) != len(other):
            return False

        # can be expensive, but we can't compare chunks one by one
        return self.unwrap() == other.unwrap()

    ### internal methods

    def _dump(self, msg=None):
        print(f"-- MEMDUMP (length: {self.length}) -- {msg if msg else ''}")
        for start, chunk in self.chunks.items():
            print(f"chunk@{start}: {chunk}")

    def _well_formed(self, msg=None):
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

    def _locate_chunk(self, offset) -> int:
        """
        Locate the chunk that contains the given offset.

        Returns the index of the chunk in the SortedDict, or -1 if not found.

        Complexity: O(log n) where n is the number of chunks (thanks to the backing SortedDict)
        """

        if offset < 0:
            raise IndexError(offset)

        NOT_FOUND = -1
        if offset >= self.length:
            return NOT_FOUND

        chunk_index = self.chunks.bisect_right(offset) - 1
        return chunk_index

    ### write operations

    def append(self, chunk: Chunk) -> None:
        """
        Append a new chunk at the end of the ByteVec.

        This does not copy the data, it just adds a reference to it.

        Complexity: O(1)
        """

        # if the data is not wrapped in a Chunk, try to wrap it
        if not isinstance(chunk, Chunk):
            chunk = Chunk.wrap(chunk)

        # do not append empty chunks
        if not chunk:
            return

        start = self.length
        self.chunks[start] = chunk
        self.length += len(chunk)

    def set_slice(self, start: int, stop: int, value: Bytes) -> None:
        # TODO
        raise NotImplementedError

    def set_byte(self, offset: int, value: Byte) -> None:
        # TODO
        raise NotImplementedError

    def __setitem__(self, key, value) -> None:
        # TODO
        raise NotImplementedError

    ### read operations

    def slice(self, start, stop) -> "ByteVec":
        """
        Return a single byte at the given offset.

        If the offset is out of bounds, the behavior is controlled by the `oob_read` attribute.

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

        first_chunk_index = self._locate_chunk(start)
        if first_chunk_index < 0:
            return self.__read_oob(expected_length)

        for chunk_start, chunk in self.chunks.items()[first_chunk_index:]:
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

    def get_byte(self, offset) -> Byte:
        """
        Return a single byte at the given offset.

        If the offset is out of bounds, the behavior is controlled by the `oob_read` attribute.

        Complexity:
        - O(log(num_chunks)) to locate the chunk
        - plus the complexity to extract a byte (O(1) on concrete chunks, O(num_bytes) on symbolic chunks)
        """

        chunk_index = self._locate_chunk(offset)
        if chunk_index < 0:
            return self.__read_oob_byte()

        chunk_start, chunk = self.chunks.peekitem(chunk_index)
        return chunk.get_byte(offset - chunk_start)

    def __getitem__(self, key) -> UnionType[Byte, "ByteVec"]:
        if isinstance(key, slice):
            start = key.start or 0
            stop = key.stop if key.stop is not None else self.length
            step = key.step or 1

            if step != 1:
                raise NotImplementedError(f"slice with step={step} not supported")

            return self.slice(start, stop)

        return self.get_byte(key)

    def __read_oob(self, num_bytes) -> Chunk:
        if self.oob_read == OOBReads.FAIL:
            raise IndexError
        else:
            return Chunk.wrap(b"\x00" * num_bytes)

    def __read_oob_byte(self) -> int:
        return self.__read_oob(1)[0]

    def unwrap(self) -> UnionType[bytes, BitVecRef]:
        """
        Return the entire ByteVec as a single value.

        This is where the actual slicing/copying is done.

        Complexity: O(n)
        """

        if not self:
            return b""

        # unwrap and defrag, ideally this becomes either a single bytes or a single BitVecRef
        data = [chunk.unwrap() for chunk in self.chunks.values()]
        data = defrag(data)
        if len(data) == 1:
            return data[0]

        # if we have multiple chunks, concatenate them
        return concat(*data)
