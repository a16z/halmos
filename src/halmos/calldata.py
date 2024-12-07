# SPDX-License-Identifier: AGPL-3.0

import re
from collections.abc import Callable
from dataclasses import dataclass
from functools import reduce

from z3 import (
    BitVec,
    BitVecRef,
)

from .bytevec import ByteVec
from .config import Config as HalmosConfig
from .logs import debug_once
from .utils import con, uid


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
    size: int  # number of bytes
    static: bool  # static vs dynamic type


@dataclass(frozen=True)
class DynamicParam:
    name: str
    size_choices: list[int]
    size_symbol: BitVecRef
    typ: Type

    def __str__(self) -> str:
        return f"{self.name}={self.size_choices}"


@dataclass(frozen=True)
class FunctionInfo:
    name: str | None = None
    sig: str | None = None
    selector: str | None = None


class Calldata:
    # For dynamic parameters not explicitly listed in --array-lengths, default sizes are used:
    # - For dynamic arrays: the size ranges from 0 to the value of --loop (inclusive).
    # - For bytes or strings: the size candidates are given by --default-bytes-lengths.
    args: HalmosConfig

    # `dyn_params` will be updated to include the fully resolved size information for all dynamic parameters.
    dyn_params: list[DynamicParam]

    # Counter for generating unique symbol names.
    # Required for create_calldata cheatcodes, which may be called multiple times.
    new_symbol_id: Callable

    def __init__(
        self,
        args: HalmosConfig,
        new_symbol_id: Callable | None,
    ) -> None:
        self.args = args
        self.dyn_params = []
        self.new_symbol_id = new_symbol_id if new_symbol_id else lambda: ""

    def get_dyn_sizes(self, name: str, typ: Type) -> tuple[list[int], BitVecRef]:
        """
        Return the list of size candidates for the given dynamic parameter.

        The candidates are derived from --array_lengths if provided; otherwise, default values are used.
        """

        sizes = self.args.array_lengths.get(name)

        if sizes is None:
            sizes = (
                self.args.default_array_lengths
                if isinstance(typ, DynamicArrayType)
                else self.args.default_bytes_lengths  # bytes or string
            )
            debug_once(
                f"no size provided for {name}; default value {sizes} will be used."
            )

        size_var = BitVec(f"p_{name}_length_{uid()}_{self.new_symbol_id():>02}", 256)

        self.dyn_params.append(DynamicParam(name, sizes, size_var, typ))

        return (sizes, size_var)

    def create(
        self, abi: dict, fun_info: FunctionInfo
    ) -> tuple[ByteVec, list[DynamicParam]]:
        """
        Create calldata of the given function.

        Returns:
            A tuple containing the generated calldata, and the size information
            for all dynamic parameters included in the calldata.
        """

        # function selector
        calldata = ByteVec()
        calldata.append(bytes.fromhex(fun_info.selector))

        # list of parameter types
        fun_abi = abi[fun_info.sig]
        tuple_type = parse_tuple_type("", fun_abi["inputs"])

        # no parameters
        if not tuple_type.items:
            return calldata, self.dyn_params

        starting_size = len(calldata)

        # ABI encoded symbolic calldata for parameters
        encoded = self.encode("", tuple_type)
        for data in encoded.data:
            calldata.append(data)

        # sanity check
        calldata_size = len(calldata) - starting_size
        if calldata_size != encoded.size:
            raise ValueError(encoded)

        return calldata, self.dyn_params

    def encode(self, name: str, typ: Type) -> EncodingResult:
        """Create symbolic ABI encoded calldata

        See https://docs.soliditylang.org/en/latest/abi-spec.html

        For dynamically-sized parameters, multiple size candidates are considered.
        A generalized encoding is used to represent these candidates, where the size field is symbolized,
        and the elements are provided assuming the maximum size of the candidates.
        The size symbols are mapped to their size candidates in the Path, and paths are later split based on these candidate values.
        (See sevm.calldataload for more details.)

        Note that this encoding approach leverages the non-uniqueness property of ABI encoding.
        In other words, the generalized encoding is not optimized for the shortest size when smaller sizes are used.
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
            sizes, size_var = self.get_dyn_sizes(name, typ)
            items = [self.encode(f"{name}[{i}]", typ.base) for i in range(max(sizes))]
            encoded = self.encode_tuple(items)
            # generalized encoding for multiple sizes
            return EncodingResult([size_var] + encoded.data, 32 + encoded.size, False)

        if isinstance(typ, BaseType):
            new_symbol = f"p_{name}_{typ.typ}_{uid()}_{self.new_symbol_id():>02}"

            # bytes, string
            if typ.typ in ["bytes", "string"]:
                sizes, size_var = self.get_dyn_sizes(name, typ)
                size = max(sizes)
                size_pad_right = ((size + 31) // 32) * 32
                data = (
                    [BitVec(new_symbol, 8 * size_pad_right)]
                    if size > 0
                    else []  # empty bytes/string
                )
                # generalized encoding for multiple sizes
                return EncodingResult([size_var] + data, 32 + size_pad_right, False)

            # uintN, intN, address, bool, bytesN
            else:
                return EncodingResult([BitVec(new_symbol, 256)], 32, True)

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


def str_abi(item: dict) -> str:
    """
    Construct a function signature string from the given function abi item.

    See `tests/test_cli.py:test_str_abi()` for examples.
    """

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


def get_abi(contract_json: dict) -> dict:
    """
    Return the mapping of function signatures to their ABI info.

    If no mapping exists, construct it using the raw ABI list.
    """

    abi_dict = contract_json.get("abi_dict")

    # construct and memoize abi mapping
    if abi_dict is None:
        abi_dict = {
            str_abi(item): item
            for item in contract_json["abi"]
            if item["type"] == "function"
        }
        contract_json["abi_dict"] = abi_dict

    return abi_dict


def mk_calldata(
    abi: dict,
    fun_info: FunctionInfo,
    args: HalmosConfig,
    new_symbol_id: Callable = None,
) -> tuple[ByteVec, list[DynamicParam]]:
    return Calldata(args, new_symbol_id).create(abi, fun_info)
