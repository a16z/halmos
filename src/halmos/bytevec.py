# SPDX-License-Identifier: AGPL-3.0

from typing import (
    Any,
    Callable,
    Dict,
    Iterator,
    List,
    Optional,
    Set,
    Tuple,
    Type,
    TypeVar,
    Union as UnionType,
)

from z3 import BitVecRef, Concat, is_bv, is_bv_value

from .exceptions import HalmosException
from .utils import *


def _defrag(data: List) -> List:
    """Merge adjacent bytes into a single element"""

    current = None


class ByteVec:
    def __init__(self, data: Optional[UnionType[bytes, str, BitVecRef, List]] = None):
        if data is None:
            data = []

        elif isinstance(data, bytes):
            data = [data]

        elif is_bv_value(data):
            data = [bv_value_to_bytes(data)]

        elif is_bv(data) and is_concat(data):
            # in the case of symbolic immutables in code, we expect a list
            # of bytes and symbolic values
            data = [
                bv_value_to_bytes(x) if is_bv_value(x) else x for x in data.children()
            ]

        elif is_bv(data):
            data = [data]

        elif isinstance(data, list):
            data = _defrag(data)

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
        slice_data = [self[pc] for pc in range(start, stop)]

        # TODO: handle empty slices
        # TODO: return a bytevec object instead of a concat expression

        # if we have any symbolic elements, return as a Concat expression
        if any(is_bv(x) for x in slice_data):
            return concat([x if is_bv(x) else con(x, 8) for x in slice_data])

        # otherwise, return as a concrete bytes object
        return bytes(slice_data)

    def __getitem__(
        self, key: UnionType[int, slice], default=None
    ) -> UnionType[int, BitVecRef]:
        """Returns the byte at the given offset (symbolic or concrete)

        default -- the value to return if the offset is out of bounds"""

        if isinstance(key, slice):
            start, stop, step = key.indices(len(self))
            if step != 1 and step != None:
                raise NotImplementedError(f"slice with step={step} not supported")

            return self.slice(start, stop)

        offset = int_of(key, "can not handle symbolic offset {offset!r}")

        # out of bounds read
        if offset < -len(self) or offset >= len(self):
            return default

        # support for negative indexing, e.g. contract[-1]
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

    def get(self, key: int, default=None) -> UnionType[int, BitVecRef]:
        return self.__getitem__(key, default=default)

    def __eq__(self, other: Any) -> bool:
        if isinstance(other, bytes):
            return self._data == [other]

        if not isinstance(other, ByteVec):
            return False

        return self._data == other._data
