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
from .utils import *


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

    def __iter__(self):
        # TODO
        raise NotImplementedError()

    def __len__(self):
        return self._length

    def slice(self, start, stop) -> "ByteVec":
        print(f"slice({start}, {stop})")
        if start >= stop:
            return ByteVec()

        # TODO: handle stop > len(self) actually
        if start < 0 or stop > len(self):
            raise HalmosException(f"unsupported slice(start={start}, stop={stop})")

        if start == stop:
            return ByteVec()

        if start == 0 and stop == len(self):
            # TODO: return self or copy? defragged or not?
            # this returns a defragged copy, leaving the original unchanged
            return ByteVec(self._data)

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

            if acc_len >= expected_length:
                if acc_len > expected_length:
                    raise HalmosException(
                        f"unexpected acc_len={acc_len} > expected_length={expected_length}"
                    )
                break

            # update the slice bounds
            start = max(0, start - elem_len)
            stop -= elem_len

        return ByteVec(acc)

    def __getitem__(
        self, key: UnionType[int, slice]
    ) -> UnionType[int, BitVecRef, "ByteVec"]:
        """Returns the byte at the given offset (symbolic or concrete)"""

        if isinstance(key, slice):
            start, stop, step = key.indices(len(self))
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
            return self._data == [other]

        if not isinstance(other, ByteVec):
            return False

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
