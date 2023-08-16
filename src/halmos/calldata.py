# SPDX-License-Identifier: AGPL-3.0

import re

from dataclasses import dataclass
from typing import List, Dict
from argparse import Namespace
from functools import reduce

from z3 import *

from .sevm import con, concat


@dataclass(frozen=True)
class Type:
    var: str


@dataclass(frozen=True)
class BaseType(Type):
    typ: str


@dataclass(frozen=True)
class FixedArrayType(Type):
    base: Type
    size: int


@dataclass(frozen=True)
class DynamicArrayType(Type):
    base: Type


@dataclass(frozen=True)
class TupleType(Type):
    items: List[Type]


def parse_type(var: str, typ: str, item: Dict) -> Type:
    """Parse ABI type in JSON format"""

    # parse array type
    match = re.search(r"^(.*)(\[([0-9]*)\])$", typ)
    if match:
        base_type = match.group(1)
        array_len = match.group(3)

        # recursively parse base type
        base = parse_type("", base_type, item)

        if array_len == "":  # dynamic array
            return DynamicArrayType(var, base)
        else:
            return FixedArrayType(var, base, int(array_len))

    # check supported type
    match = re.search(r"^(u?int[0-9]*|address|bool|bytes[0-9]*|string|tuple)$", typ)
    if not match:
        # TODO: support fixedMxN, ufixedMxN, function types
        raise NotImplementedError(f"Not supported type: {typ}")

    # parse tuple type
    if typ == "tuple":
        return parse_tuple_type(var, item["components"])

    # parse primitive types
    return BaseType(var, typ)


def parse_tuple_type(var: str, items: List[Dict]) -> Type:
    parsed_items = [parse_type(item["name"], item["type"], item) for item in items]
    return TupleType(var, parsed_items)


@dataclass(frozen=True)
class EncodingResult:
    data: List[BitVecRef]
    size: int
    static: bool


class Calldata:
    args: Namespace
    arrlen: Dict[str, int]
    dyn_param_size: List[str]  # to be updated

    def __init__(
        self, args: Namespace, arrlen: Dict[str, int], dyn_param_size: List[str]
    ) -> None:
        self.args = args
        self.arrlen = arrlen
        self.dyn_param_size = dyn_param_size

    def choose_array_len(self, name: str) -> int:
        if name in self.arrlen:
            array_len = self.arrlen[name]
        else:
            array_len = self.args.loop
            if self.args.debug:
                print(
                    f"Warning: no size provided for {name}; default value {array_len} will be used."
                )

        self.dyn_param_size.append(f"|{name}|={array_len}")

        return array_len

    def create(self, abi: Dict) -> BitVecRef:
        """Create calldata of ABI type"""

        # list of parameter types
        tuple_type = parse_tuple_type("", abi["inputs"])

        # no parameters
        if len(tuple_type.items) == 0:
            return None

        # ABI encoded symbolic calldata for parameters
        encoded = self.encode("", tuple_type)
        result = concat(encoded.data)

        # sanity check
        if result.size() != 8 * encoded.size:
            raise ValueError(encoded)

        return result

    def encode(self, name: str, typ: Type) -> EncodingResult:
        """Create symbolic ABI encoded calldata

        See https://docs.soliditylang.org/en/latest/abi-spec.html
        """

        # (T1, T2, ..., Tn)
        if isinstance(typ, TupleType):
            prefix = f"{name}." if name else ""
            items = [self.encode(f"{prefix}{item.var}", item) for item in typ.items]
            return self.encode_tuple(items)

        # T[k]
        if isinstance(typ, FixedArrayType):
            items = [self.encode(f"{name}[{i}]", typ.base) for i in range(typ.size)]
            return self.encode_tuple(items)

        # T[]
        if isinstance(typ, DynamicArrayType):
            array_len = self.choose_array_len(name)
            items = [self.encode(f"{name}[{i}]", typ.base) for i in range(array_len)]
            encoded = self.encode_tuple(items)
            return EncodingResult(
                [con(array_len)] + encoded.data, 32 + encoded.size, False
            )

        if isinstance(typ, BaseType):
            # bytes, string
            if typ.typ in ["bytes", "string"]:
                size = 65  # ECDSA signature size  # TODO: use args
                size_pad_right = ((size + 31) // 32) * 32
                data = [
                    con(size),
                    BitVec(f"p_{name}_{typ.typ}", 8 * size_pad_right),
                ]
                return EncodingResult(data, 32 + size_pad_right, False)

            # uintN, intN, address, bool, bytesN
            else:
                return EncodingResult([BitVec(f"p_{name}_{typ.typ}", 256)], 32, True)

        raise ValueError(typ)

    def encode_tuple(self, items: List[EncodingResult]) -> EncodingResult:
        # For X = (X(1), ..., X(k)):
        #
        # enc(X) = head(X(1)) ... head(X(k)) tail(X(1)) ... tail(X(k))
        #
        # if Ti is static:
        #   head(X(i)) = enc(X(i))
        #   tail(X(i)) = "" (the empty string)
        #
        # if Ti is dynamic:
        #   head(X(i)) = enc(len( head(X(1)) ... head(X(k)) tail(X(1)) ... tail(X(i-1)) ))
        #   tail(X(i)) = enc(X(i))
        #
        # See https://docs.soliditylang.org/en/latest/abi-spec.html#formal-specification-of-the-encoding

        # compute total head size
        head_size = lambda x: x.size if x.static else 32
        total_head_size = reduce(lambda s, x: s + head_size(x), items, 0)

        # generate heads and tails
        total_size = total_head_size
        heads, tails = [], []
        for item in items:
            if item.static:
                heads.extend(item.data)
            else:
                heads.append(con(total_size))
                tails.extend(item.data)
                total_size += item.size

        # tuple is static if all elements are static
        static = len(tails) == 0

        return EncodingResult(heads + tails, total_size, static)
