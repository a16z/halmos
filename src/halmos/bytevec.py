# SPDX-License-Identifier: AGPL-3.0
from abc import ABC, abstractmethod
from enum import Enum
from typing import (
    Any,
    List,
    Optional,
    Union as UnionType,
)

from z3 import BitVecRef, Concat, is_bv, is_bv_value

from .exceptions import HalmosException
from .utils import (
    byte_length,
    bv_value_to_bytes,
    eq,
    extract_bytes,
    int_of,
    is_concat,
    is_bv_value,
    try_bv_value_to_bytes,
    unbox_int,
)


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
            start, stop, step = key.start, key.stop, key.step
            if step != 1 and step != None:
                raise NotImplementedError(f"slice with step={step} not supported")

            if start is None:
                start = 0

            if stop is None:
                stop = self.length

            if not (0 <= start < self.length) or not (0 <= stop <= self.length):
                raise IndexError(key)

            return self.slice(start, stop)

        return self.byte_at(key)

    def __len__(self):
        return self.length

    @abstractmethod
    def byte_at(self, offset):
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

    def byte_at(self, offset) -> int:
        if not (0 <= offset < self.length):
            raise IndexError(offset)

        return self.data[self.start + offset]

    def slice(self, start, stop):
        return ConcreteChunk(self.data, self.start + start, stop - start)

    def unwrap(self):
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

    def byte_at(self, offset):
        if not (0 <= offset < self.length):
            raise IndexError(offset)

        return extract_bytes(self.data, self.start + offset, 1)

    def slice(self, start, stop):
        return SymbolicChunk(self.data, self.start + start, stop - start)

    def unwrap(self):
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


ByteVecInput = UnionType[bytes, str, BitVecRef, List[int]]


class ByteVecBase(ABC):
    """Abstract base class for byte vectors made of mixed concrete/symbolic byte ranges"""

    def __init__(
        self,
        data: Optional[ByteVecInput] = None,
        oob_read: OOBReads = OOBReads.RETURN_ZERO,
    ):
        if data is None:
            data = []

        elif isinstance(data, bytes):
            data = [data]

        elif is_bv_value(data):
            data = [bv_value_to_bytes(data)]

        elif is_bv(data) and is_concat(data):
            # in the case of symbolic immutables in code, we expect a list
            # of bytes and symbolic values
            data = [try_bv_value_to_bytes(x) for x in data.children()]

        elif is_bv(data):
            data = [data]

        elif isinstance(data, list):
            # first, try to convert bv values to bytes
            data = [try_bv_value_to_bytes(x) for x in data]

            # then store as defragged list
            data = defrag(data)

        elif isinstance(data, str):
            hexcode = data
            if len(hexcode) % 2 != 0:
                raise ValueError(hexcode)

            data = [bytes.fromhex(hexcode)]

        else:
            raise HalmosException(f"invalid argument: {data}")

        # check that the data is well formed
        assert all(isinstance(x, (bytes, BitVecRef)) for x in data)
        assert all(isinstance(x, (bytes, BitVecRef)) for x in data)

        self._data = data
        self._length = sum(byte_length(x) for x in data)
        self._oob_read = oob_read

    def _well_formed(self) -> bool:
        return (
            all(isinstance(x, (bytes, BitVecRef)) for x in self._data)
            and all(byte_length(x) > 0 for x in self._data)
            and self._length == sum(byte_length(x) for x in self._data)
        )

    # def __iter__(self):
    #     # TODO (commented out because it messes with pytest)
    #     raise NotImplementedError()

    def __len__(self):
        return self._length

    def slice(self, start, stop) -> "ByteVec":
        len_self = len(self)

        if start is None:
            start = 0

        if stop is None:
            stop = len_self

        if start < 0:
            raise IndexError(f"index start={start} out of bounds")

        if stop > len_self and self._oob_read == OOBReads.FAIL:
            raise IndexError(f"index stop={stop} out of bounds")

        if start == 0 and stop == len_self:
            is_immutable = not hasattr(self, "__setitem__")
            return self if is_immutable else copy.copy(self)

        if start >= stop:
            return ByteVec()

        expected_length = stop - start

        # we will store (fragments of) subelements in this list
        acc = []
        acc_len = 0

        for elem in self._data:
            # skip elements that are entirely after the slice
            if stop <= 0:
                break

            elem_len = byte_length(elem)

            # skip elements that are entirely before the slice
            if start >= elem_len:
                start -= elem_len
                stop -= elem_len
                continue

            # slice the element
            # TODO: handle case where the whole element is included (no need to slice)
            elem_stop = min(stop, elem_len)
            sliced = (
                extract_bytes(elem, start, elem_stop - start)
                if is_bv(elem)
                else elem[start:elem_stop]
            )

            acc.append(sliced)
            acc_len += elem_stop - start

            if acc_len > expected_length:
                raise HalmosException(
                    f"unexpected acc_len={acc_len} vs {expected_length}"
                )

            if acc_len == expected_length:
                break

            # update the slice bounds
            start = max(0, start - elem_len)
            stop -= elem_len

        if acc_len < expected_length:
            if self._oob_read == OOBReads.RETURN_ZERO:
                pad_len = expected_length - acc_len
                acc.append(b"\x00" * pad_len)
            else:
                raise HalmosException(
                    f"unexpected acc_len={acc_len} vs {expected_length}"
                )

        return ByteVec(acc)

    def __getitem__(
        self, key: UnionType[int, slice]
    ) -> UnionType[int, BitVecRef, "ByteVec"]:
        """Returns the byte at the given offset (symbolic or concrete)"""

        if isinstance(key, slice):
            start, stop, step = key.start, key.stop, key.step
            if step != 1 and step != None:
                raise NotImplementedError(f"slice with step={step} not supported")

            return self.slice(start, stop)

        offset = int_of(key, "can not handle symbolic offset {offset!r}")

        # out of bounds read
        if offset < -len(self) or offset >= len(self):
            if self._oob_read == OOBReads.RETURN_ZERO:
                return 0
            elif self._oob_read == OOBReads.FAIL:
                raise IndexError(f"index {offset} out of bounds")
            else:
                raise HalmosException(f"unexpected oob_read value {self._oob_read}")

        # support for negative indexing, e.g. bytevec[-1]
        if offset < 0:
            return self[len(self) + offset]

        # locate the sub-element that contains the byte at offset
        # TODO: consider using prefix sum to speed up this operation
        # TODO: consider using a binary search if the number of sub-elements is large
        for element in self._data:
            element_len = byte_length(element)

            if offset < element_len:
                # symbolic case
                if is_bv(element):
                    extracted = extract_bytes(element, offset, 1)

                    # return as concrete if possible
                    return unbox_int(extracted)

                # concrete case
                return element[offset]

            offset -= element_len

        # should never reach here
        raise HalmosException(f"failed to locate offset={offset} in {self._data}")

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, bytes):
            if len(other) != len(self):
                return False
            return self._data == [other]

        if not isinstance(other, ByteVec):
            return False

        # XXX: direct comparison fails for fragmented but equivalent data
        return self._data == other._data

    def __repr__(self) -> str:
        return f"ByteVec({self._data})"

    def __bool__(self) -> bool:
        return bool(self._length)


class ByteVec(ByteVecBase):
    """Immutable ByteVec implementation"""

    def __init__(
        self,
        data: Optional[ByteVecInput] = None,
        oob_read: OOBReads = OOBReads.RETURN_ZERO,
    ):
        super().__init__(data, oob_read)


class MutByteVec(ByteVecBase):
    """Mutable ByteVec implementation"""

    def __init__(
        self,
        data: Optional[ByteVecInput] = None,
        oob_read: OOBReads = OOBReads.RETURN_ZERO,
    ):
        super().__init__(data, oob_read)

    def __setitem__(self, key, value) -> None:
        # arg1 can be an index or slice(start, stop, step=None)
        # arg2 is bytes or ByteVec
        raise NotImplementedError("TODO: __setitem__")
