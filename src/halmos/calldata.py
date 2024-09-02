# SPDX-License-Identifier: AGPL-3.0

import re
from dataclasses import dataclass
from functools import reduce

from z3 import (
    BitVec,
    BitVecRef,
)

from .bytevec import ByteVec
from .config import Config as HalmosConfig
from .utils import con


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
    items: list[Type]


def parse_type(var: str, typ: str, item: dict) -> Type:
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


def parse_tuple_type(var: str, items: list[dict]) -> Type:
    parsed_items = [parse_type(item["name"], item["type"], item) for item in items]
    return TupleType(var, parsed_items)


@dataclass(frozen=True)
class EncodingResult:
    data: list[BitVecRef]
    size: int
    static: bool


class Calldata:
    args: HalmosConfig
    arrlen: dict[str, int]
    dyn_param_size: list[str]  # to be updated

    def __init__(
        self, args: HalmosConfig, arrlen: dict[str, int], dyn_param_size: list[str]
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

    def create(self, abi: dict, output: ByteVec) -> None:
        """Create calldata of ABI type, and append to output"""

        # list of parameter types
        tuple_type = parse_tuple_type("", abi["inputs"])

        # no parameters
        if len(tuple_type.items) == 0:
            return

        starting_size = len(output)

        # ABI encoded symbolic calldata for parameters
        encoded = self.encode("", tuple_type)
        for data in encoded.data:
            output.append(data)

        # sanity check
        calldata_size = len(output) - starting_size
        if calldata_size != encoded.size:
            raise ValueError(encoded)

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

    def encode_tuple(self, items: list[EncodingResult]) -> EncodingResult:
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
        def head_size(x):
            return x.size if x.static else 32

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


@dataclass(frozen=True)
class FunctionInfo:
    name: str | None = None
    sig: str | None = None
    selector: str | None = None


def str_abi(item: dict) -> str:
    def str_tuple(args: list) -> str:
        ret = []
        for arg in args:
            typ = arg["type"]
            match = re.search(r"^tuple((\[[0-9]*\])*)$", typ)
            if match:
                ret.append(str_tuple(arg["components"]) + match.group(1))
            else:
                ret.append(typ)
        return "(" + ",".join(ret) + ")"

    if item["type"] != "function":
        raise ValueError(item)
    return item["name"] + str_tuple(item["inputs"])


def find_abi(abi: list, fun_info: FunctionInfo) -> dict:
    funname, funsig = fun_info.name, fun_info.sig
    for item in abi:
        if (
            item["type"] == "function"
            and item["name"] == funname
            and str_abi(item) == funsig
        ):
            return item
    raise ValueError(f"No {funsig} found in {abi}")


def mk_calldata(
    abi: list,
    fun_info: FunctionInfo,
    cd: ByteVec,
    dyn_param_size: list[str],
    args: HalmosConfig,
) -> None:
    # find function abi
    fun_abi = find_abi(abi, fun_info)

    # no parameters
    if len(fun_abi["inputs"]) == 0:
        return

    # generate symbolic ABI calldata
    calldata = Calldata(args, mk_arrlen(args), dyn_param_size)
    calldata.create(fun_abi, cd)


def mk_arrlen(args: HalmosConfig) -> dict[str, int]:
    arrlen = {}
    if args.array_lengths:
        for assign in [x.split("=") for x in args.array_lengths.split(",")]:
            name = assign[0].strip()
            size = assign[1].strip()
            arrlen[name] = int(size)
    return arrlen
