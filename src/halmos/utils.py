# SPDX-License-Identifier: AGPL-3.0

from __future__ import annotations

import math
import re
import uuid
from functools import partial
from timeit import default_timer as timer
from typing import TYPE_CHECKING, Any, TypeAlias, Union

from z3 import (
    Z3_OP_BADD,
    Z3_OP_CONCAT,
    Z3_OP_ULEQ,
    And,
    BitVec,
    BitVecNumRef,
    BitVecRef,
    BitVecSort,
    BitVecVal,
    BoolRef,
    BoolVal,
    Concat,
    Extract,
    Function,
    If,
    Not,
    Or,
    SignExt,
    Solver,
    SolverFor,
    eq,
    is_app,
    is_app_of,
    is_bool,
    is_bv,
    is_bv_value,
    is_const,
    is_not,
    simplify,
    substitute,
)

from halmos.bitvec import HalmosBitVec as BV
from halmos.bitvec import HalmosBool as Bool
from halmos.exceptions import HalmosException, NotConcreteError
from halmos.hashes import keccak256_256, keccak256_512
from halmos.logs import warn
from halmos.mapper import Mapper

# order of the secp256k1 curve
secp256k1n = (
    115792089237316195423570985008687907852837564279074904382605163141518161494337
)

if TYPE_CHECKING:
    from halmos.bytevec import ByteVec

Byte = int | BitVecRef | BV  # uint8
Bytes4 = int | BitVecRef | BV  # uint32
Address = int | BitVecRef | BV  # uint160
Word = int | BitVecRef | BV  # uint256
Bytes: TypeAlias = Union[
    bytes, BitVecRef, "ByteVec"
]  # arbitrary-length sequence of bytes


# dynamic BitVecSort sizes
class BitVecSortCache:
    def __init__(self):
        self.cache = {}
        for size in (
            1,
            8,
            16,
            32,
            64,
            128,
            160,
            256,
            264,
            288,
            512,
            544,
            800,
            1024,
            1056,
        ):
            self.cache[size] = BitVecSort(size)

    def __getitem__(self, size: int) -> BitVecSort:
        hit = self.cache.get(size)
        return hit if hit is not None else BitVecSort(size)


BitVecSorts = BitVecSortCache()

# known, fixed BitVecSort sizes
BitVecSort1 = BitVecSorts[1]
BitVecSort8 = BitVecSorts[8]
BitVecSort160 = BitVecSorts[160]
BitVecSort256 = BitVecSorts[256]
BitVecSort264 = BitVecSorts[264]
BitVecSort512 = BitVecSorts[512]


# ecrecover(digest, v, r, s)
f_ecrecover = Function(
    "f_ecrecover",
    BitVecSort256,
    BitVecSort8,
    BitVecSort256,
    BitVecSort256,
    BitVecSort160,
)


def is_f_sha3_name(name: str) -> bool:
    return name.startswith("f_sha3_")


def f_sha3_name(bitsize: int) -> str:
    return f"f_sha3_{bitsize}"


def f_inv_sha3_name(bitsize: int) -> str:
    return f"f_inv_sha3_{bitsize}"


# TODO: explore the impact of using a smaller bitsize for the range sort
f_inv_sha3_size = Function("f_inv_sha3_size", BitVecSort160, BitVecSort256)


f_sha3_0_name = f_sha3_name(0)
f_sha3_256_name = f_sha3_name(256)
f_sha3_512_name = f_sha3_name(512)

# NOTE: another way to encode the empty keccak is to use 0-ary function like:
#         f_sha3_empty = Function(f_sha3_0_name, BitVecSort256)
#       then `f_sha3_empty()` is equivalent to `BitVec(f_sha3_0_name, BitVecSort256)`.
#       in both cases, decl() == f_sha3_0_name, and num_args() == 0.
f_sha3_empty = BitVec(f_sha3_0_name, BitVecSort256)

f_sha3_256 = Function(f_sha3_256_name, BitVecSort256, BitVecSort256)
f_sha3_512 = Function(f_sha3_512_name, BitVecSort512, BitVecSort256)


def uid() -> str:
    return uuid.uuid4().hex[:7]


def wrap(x: Any) -> Word:
    if is_bv(x):
        return x
    if isinstance(x, int):
        return con(x)
    if isinstance(x, bytes):
        return BitVecVal(int.from_bytes(x, "big"), 8 * len(x))
    raise ValueError(x)


def concat(args):
    if len(args) > 1:
        return Concat([wrap(x) for x in args])
    else:
        return args[0]


def smt_or(args):
    if len(args) > 1:
        return Or(args)
    else:
        return args[0]


def smt_and(args):
    if len(args) > 1:
        return And(args)
    else:
        return args[0]


def uint(x: Any, n: int) -> Word:
    """
    Truncates or zero-extends x to n bits
    """

    return BV(x, size=n)


def uint8(x: Any) -> Byte:
    return uint(x, 8)


def uint160(x: Word) -> Address:
    return uint(x, 160)


def uint256(x: Any) -> Word:
    return uint(x, 256)


def int256(x: Any) -> Word:
    if isinstance(x, int):
        return con(x, size_bits=256)

    if is_bool(x):
        return If(x, con(1, size_bits=256), con(0, size_bits=256))

    bitsize = x.size()
    if bitsize > 256:
        raise ValueError(x)
    if bitsize == 256:
        return x
    return simplify(SignExt(256 - bitsize, x))


def address(x: Any) -> Address:
    return uint(x, 160)


def con(n: int, size_bits=256) -> Word:
    return BitVecVal(n, BitVecSorts[size_bits])


def con_addr(n: int) -> BitVecRef:
    if n >= 2**160:
        raise ValueError(n)
    return BitVecVal(n, 160)


def z3_bv(x: Any) -> BitVecRef:
    if isinstance(x, BV):
        return x.as_z3()

    if isinstance(x, Bool):
        return BV(x).as_z3()

    # must check before int because isinstance(True, int) is True
    if isinstance(x, bool):
        return BoolVal(x)

    if isinstance(x, int):
        return con(x, size_bits=256)

    if is_bv(x) or is_bool(x):
        return x

    raise ValueError(x)


#             x  == b   if sort(x) = bool
# int_to_bool(x) == b   if sort(x) = int
def test(x: Word, b: bool) -> BoolRef:
    if isinstance(x, int):
        return BoolVal(x != 0) if b else BoolVal(x == 0)

    elif isinstance(x, BV):
        return x.is_non_zero().as_z3() if b else x.is_zero().as_z3()

    elif is_bool(x):
        if b:
            return x
        else:
            return Not(x)

    elif is_bv(x):
        return x != con(0) if b else x == con(0)

    else:
        raise ValueError(x)


def is_concrete(x: Any) -> bool:
    if isinstance(x, BV | Bool):
        return x.is_concrete

    return isinstance(x, int | bytes) or is_bv_value(x)


def is_concat(x: BitVecRef) -> bool:
    return is_app_of(x, Z3_OP_CONCAT)


def create_solver(logic="QF_AUFBV", ctx=None, timeout=0, max_memory=0) -> Solver:
    # QF_AUFBV: quantifier-free bitvector + array theory: https://smtlib.cs.uiowa.edu/logics.shtml
    solver = SolverFor(logic, ctx=ctx)

    # set timeout
    solver.set(timeout=timeout)

    # set memory limit
    if max_memory > 0:
        solver.set(max_memory=max_memory)

    return solver


def extract_bytes32_array_argument(data: Bytes, arg_idx: int) -> Bytes:
    """Extracts idx-th argument of bytes32[] from calldata"""
    offset = int_of(
        extract_bytes(data, 4 + arg_idx * 32, 32),
        "symbolic offset for bytes argument",
    )
    length = int_of(
        extract_bytes(data, 4 + offset, 32),
        "symbolic size for bytes argument",
    )
    if length == 0:
        return b""

    return extract_bytes(data, 4 + offset + 32, length * 32)


def extract_bytes_argument(data: Bytes, arg_idx: int) -> bytes:
    """Extracts idx-th argument of string from data"""
    offset = int_of(
        extract_word(data, 4 + arg_idx * 32), "symbolic offset for bytes argument"
    )
    length = int_of(extract_word(data, 4 + offset), "symbolic size for bytes argument")
    if length == 0:
        return b""

    bytes = extract_bytes(data, 4 + offset + 32, length)
    return bv_value_to_bytes(bytes) if is_bv_value(bytes) else bytes


def extract_string_argument(data: Bytes, arg_idx: int) -> Bytes:
    """Extracts idx-th argument of string from data"""
    string_bytes = extract_bytes_argument(data, arg_idx)
    return string_bytes.decode("utf-8") if is_concrete(string_bytes) else string_bytes


def extract_bytes(data: Bytes, offset: int, size_bytes: int) -> Bytes:
    """Extract bytes from data. Zero-pad if out of bounds."""
    if hasattr(data, "__getitem__"):
        data_slice = data[offset : offset + size_bytes]
        return data_slice.unwrap() if hasattr(data_slice, "unwrap") else data_slice

    if data is None:
        return BitVecVal(0, size_bytes * 8)

    n = data.size()
    if n % 8 != 0:
        raise ValueError(n)

    # will extract hi - lo + 1 bits
    hi = n - 1 - offset * 8
    lo = n - offset * 8 - size_bytes * 8
    lo = 0 if lo < 0 else lo

    val = simplify(Extract(hi, lo, data))

    zero_padding = size_bytes * 8 - val.size()
    if zero_padding < 0:
        raise ValueError(val)
    if zero_padding > 0:
        val = simplify(Concat(val, con(0, zero_padding)))

    return val


def extract_word(data: Bytes, offset: int) -> Word:
    """Extracts a 256-bit word from data at offset"""
    return extract_bytes(data, offset, 32)


def extract_funsig(data: Bytes) -> Bytes4:
    """Extracts the function signature (first 4 bytes) from calldata"""
    if hasattr(data, "__getitem__"):
        return unbox_int(data[:4])
    return extract_bytes(data, 0, 4)


def bv_value_to_bytes(x: BitVecNumRef) -> bytes:
    return x.as_long().to_bytes(byte_length(x, strict=True), "big")


def try_bv_value_to_bytes(x: Any) -> Any:
    return bv_value_to_bytes(x) if is_bv_value(x) else x


def bytes_to_bv_value(x: bytes) -> BitVecNumRef:
    return con(int.from_bytes(x, "big"), size_bits=len(x) * 8)


def try_bytes_to_bv_value(x: Any) -> Any:
    return bytes_to_bv_value(x) if isinstance(x, bytes) else x


def unbox_int(x: Any) -> Any:
    """
    Converts int-like objects to int, returns x otherwise
    """
    if isinstance(x, int):
        return x

    if hasattr(x, "unwrap"):
        return unbox_int(x.unwrap())

    if isinstance(x, bytes):
        return int.from_bytes(x, "big")

    if is_bv_value(x):
        return x.as_long()

    return x


def int_of(x: Any, err: str = None, subst: dict = None) -> int:
    """
    Converts int-like objects to int or raises NotConcreteError
    """

    if hasattr(x, "unwrap"):
        x = x.unwrap()

    # attempt to replace symbolic (sub-)terms with their concrete values
    if subst and is_bv(x) and not is_bv_value(x):
        x = simplify(substitute(x, *subst.items()))

    res = unbox_int(x)

    if isinstance(res, int):
        return res

    err = err or "expected concrete value but got"
    raise NotConcreteError(f"{err}: {hexify(x)}")


def byte_length(x: Any, strict=True) -> int:
    if hasattr(x, "__len__"):
        # bytes, lists, tuples, bytevecs, chunks...
        return len(x)

    if is_bv(x):
        if x.size() % 8 != 0 and strict:
            raise HalmosException(f"byte_length({x}) with bit size {x.size()}")
        return math.ceil(x.size() / 8)

    raise TypeError(f"byte_length({x}) of type {type(x)}")


def match_dynamic_array_overflow_condition(cond: BitVecRef) -> bool:
    """
    Check if `cond` matches the following pattern:
        Not(ULE(f_sha3_N(slot), offset + f_sha3_N(slot))), where offset < 2**64

    This condition is satisfied when a dynamic array at `slot` exceeds the storage limit.
    Since such an overflow is highly unlikely in practice, we assume that this condition is unsat.

    Note: we already assume that any sha3 hash output is smaller than 2**256 - 2**64 (see SEVM.sha3_data()).
    However, the smt solver may not be able to solve this condition within the branching timeout.
    In such cases, this explicit pattern serves as a fallback to avoid exploring practically infeasible paths.

    We don't need to handle the negation of this condition, because unknown conditions are conservatively assumed to be sat.
    """

    # Not(ule)
    if not is_not(cond):
        return False
    ule = cond.arg(0)

    # Not(ULE(left, right)
    if not is_app_of(ule, Z3_OP_ULEQ):
        return False
    left, right = ule.arg(0), ule.arg(1)

    # Not(ULE(f_sha3_N(slot), offset + base))
    if not (is_f_sha3_name(left.decl().name()) and is_app_of(right, Z3_OP_BADD)):
        return False
    offset, base = right.arg(0), right.arg(1)

    # Not(ULE(f_sha3_N(slot), offset + f_sha3_N(slot))) and offset < 2**64
    return eq(left, base) and is_bv_value(offset) and offset.as_long() < 2**64


def stripped(hexstring: str) -> str:
    """Remove 0x prefix from hexstring"""
    return hexstring[2:] if hexstring.startswith("0x") else hexstring


def decode_hex(hexstring: str) -> bytes | None:
    try:
        # not checking if length is even because fromhex accepts spaces
        return bytes.fromhex(stripped(hexstring))
    except ValueError:
        return None


def hexify(x, contract_name: str = None):
    if isinstance(x, str):
        return re.sub(r"\b(\d+)\b", lambda match: hex(int(match.group(1))), x)
    elif isinstance(x, int):
        return f"0x{x:02x}"
    elif isinstance(x, bytes):
        return Mapper().lookup_selector("0x" + x.hex(), contract_name)
    elif hasattr(x, "unwrap"):
        return hexify(x.unwrap(), contract_name)
    elif is_bv_value(x):
        # maintain the byte size of x
        num_bytes = byte_length(x, strict=False)
        return Mapper().lookup_selector(
            f"0x{x.as_long():0{num_bytes * 2}x}", contract_name
        )
    elif is_app(x):
        params_and_children = (
            f"({', '.join(map(partial(hexify, contract_name=contract_name), x.params() + x.children()))})"
            if not is_const(x)
            else ""
        )
        return f"{str(x.decl())}{params_and_children}"
    else:
        return hexify(str(x), contract_name)


def render_uint(x: BitVecRef) -> str:
    if is_bv_value(x):
        val = int_of(x)
        return f"0x{val:0{byte_length(x, strict=False) * 2}x} ({val})"

    return hexify(x)


def render_int(x: BitVecRef) -> str:
    if is_bv_value(x):
        val = x.as_signed_long()
        return f"0x{x.as_long():0{byte_length(x, strict=False) * 2}x} ({val})"

    return hexify(x)


def render_bool(b: BitVecRef) -> str:
    return str(b.as_long() != 0).lower() if is_bv_value(b) else hexify(b)


def render_string(s: BitVecRef) -> str:
    str_val = bytes.fromhex(stripped(hexify(s))).decode("utf-8")
    return f'"{str_val}"'


def render_bytes(b: Bytes) -> str:
    if is_bv(b):
        return hexify(b) + f" ({byte_length(b, strict=False)} bytes)"
    else:
        return f'hex"{stripped(b.hex())}"'


def render_address(a: BitVecRef) -> str:
    if is_bv_value(a):
        return f"0x{a.as_long():040x}"

    return hexify(a)


def stringify(symbol_name: str, val: Any):
    """
    Formats a value based on the inferred type of the variable.

    Expects symbol_name to be of the form 'p_<sourceVar>_<sourceType>', e.g. 'p_x_uint256'
    """
    if not is_bv_value(val):
        warn(f"{val} is not a bitvector value")
        return hexify(val)

    tokens = symbol_name.split("_")
    if len(tokens) < 3:
        warn(f"Failed to infer type for symbol '{symbol_name}'")
        return hexify(val)

    if len(tokens) >= 4 and tokens[-1].isdigit():
        # we may have something like p_val_bytes_01
        # the last token being a symbol number, discard it
        tokens.pop()

    type_name = tokens[-1]

    try:
        if type_name.startswith("uint"):
            return render_uint(val)
        elif type_name.startswith("int"):
            return render_int(val)
        elif type_name == "bool":
            return render_bool(val)
        elif type_name == "string":
            return render_string(val)
        elif type_name == "bytes":
            return render_bytes(val)
        elif type_name == "address":
            return render_address(val)
        else:  # bytes32, bytes4, structs, etc.
            return hexify(val)
    except Exception as e:
        # log error and move on
        warn(f"Failed to stringify {val} of type {type_name}: {repr(e)}")
        return hexify(val)


def assert_bv(x) -> None:
    if not is_bv(x):
        raise ValueError(x)


def assert_address(x: Word) -> None:
    if isinstance(x, BV):
        if x.size != 160:
            raise ValueError(x)
        return

    if is_concrete(x):
        if not 0 <= int_of(x) < 2**160:
            raise ValueError(x)
        return

    if x.size() != 160:
        raise ValueError(x)


def assert_uint256(x: Word) -> None:
    if isinstance(x, BV):
        if x.size != 256:
            raise ValueError(x)
        return

    if is_concrete(x):
        if not 0 <= int_of(x) < 2**256:
            raise ValueError(x)
        return

    if x.size() != 256:
        raise ValueError(x)


def green(text: str) -> str:
    return f"\033[32m{text}\033[0m"


def red(text: str) -> str:
    return f"\033[31m{text}\033[0m"


def yellow(text: str) -> str:
    return f"\033[33m{text}\033[0m"


def cyan(text: str) -> str:
    return f"\033[36m{text}\033[0m"


def magenta(text: str) -> str:
    return f"\033[95m{text}\033[0m"


color_good = green
color_debug = magenta
color_info = cyan
color_warn = yellow
color_error = red


def indent_text(text: str, n: int = 4) -> str:
    return "\n".join(" " * n + line for line in text.splitlines())


class EVM:
    STOP = 0x00
    ADD = 0x01
    MUL = 0x02
    SUB = 0x03
    DIV = 0x04
    SDIV = 0x05
    MOD = 0x06
    SMOD = 0x07
    ADDMOD = 0x08
    MULMOD = 0x09
    EXP = 0x0A
    SIGNEXTEND = 0x0B
    LT = 0x10
    GT = 0x11
    SLT = 0x12
    SGT = 0x13
    EQ = 0x14
    ISZERO = 0x15
    AND = 0x16
    OR = 0x17
    XOR = 0x18
    NOT = 0x19
    BYTE = 0x1A
    SHL = 0x1B
    SHR = 0x1C
    SAR = 0x1D
    SHA3 = 0x20
    ADDRESS = 0x30
    BALANCE = 0x31
    ORIGIN = 0x32
    CALLER = 0x33
    CALLVALUE = 0x34
    CALLDATALOAD = 0x35
    CALLDATASIZE = 0x36
    CALLDATACOPY = 0x37
    CODESIZE = 0x38
    CODECOPY = 0x39
    GASPRICE = 0x3A
    EXTCODESIZE = 0x3B
    EXTCODECOPY = 0x3C
    RETURNDATASIZE = 0x3D
    RETURNDATACOPY = 0x3E
    EXTCODEHASH = 0x3F
    BLOCKHASH = 0x40
    COINBASE = 0x41
    TIMESTAMP = 0x42
    NUMBER = 0x43
    DIFFICULTY = 0x44
    GASLIMIT = 0x45
    CHAINID = 0x46
    SELFBALANCE = 0x47
    BASEFEE = 0x48
    POP = 0x50
    MLOAD = 0x51
    MSTORE = 0x52
    MSTORE8 = 0x53
    SLOAD = 0x54
    SSTORE = 0x55
    JUMP = 0x56
    JUMPI = 0x57
    PC = 0x58
    MSIZE = 0x59
    GAS = 0x5A
    JUMPDEST = 0x5B
    TLOAD = 0x5C
    TSTORE = 0x5D
    MCOPY = 0x5E
    PUSH0 = 0x5F
    PUSH1 = 0x60
    PUSH2 = 0x61
    PUSH3 = 0x62
    PUSH4 = 0x63
    PUSH5 = 0x64
    PUSH6 = 0x65
    PUSH7 = 0x66
    PUSH8 = 0x67
    PUSH9 = 0x68
    PUSH10 = 0x69
    PUSH11 = 0x6A
    PUSH12 = 0x6B
    PUSH13 = 0x6C
    PUSH14 = 0x6D
    PUSH15 = 0x6E
    PUSH16 = 0x6F
    PUSH17 = 0x70
    PUSH18 = 0x71
    PUSH19 = 0x72
    PUSH20 = 0x73
    PUSH21 = 0x74
    PUSH22 = 0x75
    PUSH23 = 0x76
    PUSH24 = 0x77
    PUSH25 = 0x78
    PUSH26 = 0x79
    PUSH27 = 0x7A
    PUSH28 = 0x7B
    PUSH29 = 0x7C
    PUSH30 = 0x7D
    PUSH31 = 0x7E
    PUSH32 = 0x7F
    DUP1 = 0x80
    DUP2 = 0x81
    DUP3 = 0x82
    DUP4 = 0x83
    DUP5 = 0x84
    DUP6 = 0x85
    DUP7 = 0x86
    DUP8 = 0x87
    DUP9 = 0x88
    DUP10 = 0x89
    DUP11 = 0x8A
    DUP12 = 0x8B
    DUP13 = 0x8C
    DUP14 = 0x8D
    DUP15 = 0x8E
    DUP16 = 0x8F
    SWAP1 = 0x90
    SWAP2 = 0x91
    SWAP3 = 0x92
    SWAP4 = 0x93
    SWAP5 = 0x94
    SWAP6 = 0x95
    SWAP7 = 0x96
    SWAP8 = 0x97
    SWAP9 = 0x98
    SWAP10 = 0x99
    SWAP11 = 0x9A
    SWAP12 = 0x9B
    SWAP13 = 0x9C
    SWAP14 = 0x9D
    SWAP15 = 0x9E
    SWAP16 = 0x9F
    LOG0 = 0xA0
    LOG1 = 0xA1
    LOG2 = 0xA2
    LOG3 = 0xA3
    LOG4 = 0xA4
    CREATE = 0xF0
    CALL = 0xF1
    CALLCODE = 0xF2
    RETURN = 0xF3
    DELEGATECALL = 0xF4
    CREATE2 = 0xF5
    STATICCALL = 0xFA
    REVERT = 0xFD
    INVALID = 0xFE
    SELFDESTRUCT = 0xFF


str_opcode: dict[int, str] = {
    EVM.STOP: "STOP",
    EVM.ADD: "ADD",
    EVM.MUL: "MUL",
    EVM.SUB: "SUB",
    EVM.DIV: "DIV",
    EVM.SDIV: "SDIV",
    EVM.MOD: "MOD",
    EVM.SMOD: "SMOD",
    EVM.ADDMOD: "ADDMOD",
    EVM.MULMOD: "MULMOD",
    EVM.EXP: "EXP",
    EVM.SIGNEXTEND: "SIGNEXTEND",
    EVM.LT: "LT",
    EVM.GT: "GT",
    EVM.SLT: "SLT",
    EVM.SGT: "SGT",
    EVM.EQ: "EQ",
    EVM.ISZERO: "ISZERO",
    EVM.AND: "AND",
    EVM.OR: "OR",
    EVM.XOR: "XOR",
    EVM.NOT: "NOT",
    EVM.BYTE: "BYTE",
    EVM.SHL: "SHL",
    EVM.SHR: "SHR",
    EVM.SAR: "SAR",
    EVM.SHA3: "SHA3",
    EVM.ADDRESS: "ADDRESS",
    EVM.BALANCE: "BALANCE",
    EVM.ORIGIN: "ORIGIN",
    EVM.CALLER: "CALLER",
    EVM.CALLVALUE: "CALLVALUE",
    EVM.CALLDATALOAD: "CALLDATALOAD",
    EVM.CALLDATASIZE: "CALLDATASIZE",
    EVM.CALLDATACOPY: "CALLDATACOPY",
    EVM.CODESIZE: "CODESIZE",
    EVM.CODECOPY: "CODECOPY",
    EVM.GASPRICE: "GASPRICE",
    EVM.EXTCODESIZE: "EXTCODESIZE",
    EVM.EXTCODECOPY: "EXTCODECOPY",
    EVM.RETURNDATASIZE: "RETURNDATASIZE",
    EVM.RETURNDATACOPY: "RETURNDATACOPY",
    EVM.EXTCODEHASH: "EXTCODEHASH",
    EVM.BLOCKHASH: "BLOCKHASH",
    EVM.COINBASE: "COINBASE",
    EVM.TIMESTAMP: "TIMESTAMP",
    EVM.NUMBER: "NUMBER",
    EVM.DIFFICULTY: "DIFFICULTY",
    EVM.GASLIMIT: "GASLIMIT",
    EVM.CHAINID: "CHAINID",
    EVM.SELFBALANCE: "SELFBALANCE",
    EVM.BASEFEE: "BASEFEE",
    EVM.POP: "POP",
    EVM.MCOPY: "MCOPY",
    EVM.MLOAD: "MLOAD",
    EVM.MSTORE: "MSTORE",
    EVM.MSTORE8: "MSTORE8",
    EVM.SLOAD: "SLOAD",
    EVM.SSTORE: "SSTORE",
    EVM.JUMP: "JUMP",
    EVM.JUMPI: "JUMPI",
    EVM.PC: "PC",
    EVM.MSIZE: "MSIZE",
    EVM.GAS: "GAS",
    EVM.JUMPDEST: "JUMPDEST",
    EVM.TLOAD: "TLOAD",
    EVM.TSTORE: "TSTORE",
    EVM.MCOPY: "MCOPY",
    EVM.PUSH0: "PUSH0",
    EVM.PUSH1: "PUSH1",
    EVM.PUSH2: "PUSH2",
    EVM.PUSH3: "PUSH3",
    EVM.PUSH4: "PUSH4",
    EVM.PUSH5: "PUSH5",
    EVM.PUSH6: "PUSH6",
    EVM.PUSH7: "PUSH7",
    EVM.PUSH8: "PUSH8",
    EVM.PUSH9: "PUSH9",
    EVM.PUSH10: "PUSH10",
    EVM.PUSH11: "PUSH11",
    EVM.PUSH12: "PUSH12",
    EVM.PUSH13: "PUSH13",
    EVM.PUSH14: "PUSH14",
    EVM.PUSH15: "PUSH15",
    EVM.PUSH16: "PUSH16",
    EVM.PUSH17: "PUSH17",
    EVM.PUSH18: "PUSH18",
    EVM.PUSH19: "PUSH19",
    EVM.PUSH20: "PUSH20",
    EVM.PUSH21: "PUSH21",
    EVM.PUSH22: "PUSH22",
    EVM.PUSH23: "PUSH23",
    EVM.PUSH24: "PUSH24",
    EVM.PUSH25: "PUSH25",
    EVM.PUSH26: "PUSH26",
    EVM.PUSH27: "PUSH27",
    EVM.PUSH28: "PUSH28",
    EVM.PUSH29: "PUSH29",
    EVM.PUSH30: "PUSH30",
    EVM.PUSH31: "PUSH31",
    EVM.PUSH32: "PUSH32",
    EVM.DUP1: "DUP1",
    EVM.DUP2: "DUP2",
    EVM.DUP3: "DUP3",
    EVM.DUP4: "DUP4",
    EVM.DUP5: "DUP5",
    EVM.DUP6: "DUP6",
    EVM.DUP7: "DUP7",
    EVM.DUP8: "DUP8",
    EVM.DUP9: "DUP9",
    EVM.DUP10: "DUP10",
    EVM.DUP11: "DUP11",
    EVM.DUP12: "DUP12",
    EVM.DUP13: "DUP13",
    EVM.DUP14: "DUP14",
    EVM.DUP15: "DUP15",
    EVM.DUP16: "DUP16",
    EVM.SWAP1: "SWAP1",
    EVM.SWAP2: "SWAP2",
    EVM.SWAP3: "SWAP3",
    EVM.SWAP4: "SWAP4",
    EVM.SWAP5: "SWAP5",
    EVM.SWAP6: "SWAP6",
    EVM.SWAP7: "SWAP7",
    EVM.SWAP8: "SWAP8",
    EVM.SWAP9: "SWAP9",
    EVM.SWAP10: "SWAP10",
    EVM.SWAP11: "SWAP11",
    EVM.SWAP12: "SWAP12",
    EVM.SWAP13: "SWAP13",
    EVM.SWAP14: "SWAP14",
    EVM.SWAP15: "SWAP15",
    EVM.SWAP16: "SWAP16",
    EVM.LOG0: "LOG0",
    EVM.LOG1: "LOG1",
    EVM.LOG2: "LOG2",
    EVM.LOG3: "LOG3",
    EVM.LOG4: "LOG4",
    EVM.CREATE: "CREATE",
    EVM.CALL: "CALL",
    EVM.CALLCODE: "CALLCODE",
    EVM.RETURN: "RETURN",
    EVM.DELEGATECALL: "DELEGATECALL",
    EVM.CREATE2: "CREATE2",
    EVM.STATICCALL: "STATICCALL",
    EVM.REVERT: "REVERT",
    EVM.INVALID: "INVALID",
    EVM.SELFDESTRUCT: "SELFDESTRUCT",
}


class OffsetMap:
    """A specialized mapping class that splits integer keys into two parts for efficient storage and lookup.

    Keys are split into:
    1. High-order bits used as the main dictionary key
    2. Low-order bits (offset) stored with the value

    For example, with offset_bits=16:
    - Key 0x1234567890 is split into:
      - High part: 0x123456 (dictionary key)
      - Low part: 0x7890 (offset)

    Useful for storing values where keys are related by small offsets.
    """

    def __init__(self, offset_bits: int = 16):
        """Initialize the OffsetMap.

        Args:
            offset_bits: Number of bits to use for the offset part of the key.
                        The remaining bits are used as the main dictionary key.
        """
        self._map = {}
        self._offset_bits = offset_bits
        self._mask = (1 << offset_bits) - 1  # Creates a mask of offset_bits 1's

    def __getitem__(self, key: int) -> tuple[int, int] | tuple[None, None]:
        """Get the value and offset delta for a key.

        Args:
            key: The integer key to look up

        Returns:
            A tuple of (value, delta) where:
            - value is the stored value (or None if not found)
            - delta is the difference between the requested offset and stored offset
              Note: delta can be negative, e.g., when computing slot(a[n-1]) which is `(keccak(slot(a)) - 1) + n`
        """
        (value, offset) = self._map.get(key >> self._offset_bits, (None, None))
        if value is None:
            return (None, None)
        delta = (key & self._mask) - offset
        return (value, delta)

    def __setitem__(self, key: int, value: Any):
        """Store a value with its offset.

        Args:
            key: The integer key to store
            value: The value to store
        """
        raw_key = key >> self._offset_bits
        raw_value = (value, key & self._mask)
        assert (existing := self._map.get(raw_key)) is None or existing == raw_value
        self._map[raw_key] = raw_value

    def copy(self) -> OffsetMap:
        new_map = OffsetMap(self._offset_bits)
        new_map._map = self._map.copy()
        return new_map


def mk_precomputed_keccak_registry() -> OffsetMap:
    m = OffsetMap()
    for k, v in keccak256_256.items():
        m[k] = f_sha3_256(con(v))
    for k, (v1, v2) in keccak256_512.items():
        m[k] = f_sha3_512(con((v1 << 256) + v2, size_bits=512))
    return m


precomputed_keccak_registry: OffsetMap = mk_precomputed_keccak_registry()


class NamedTimer:
    def __init__(self, name: str, auto_start=True):
        self.name = name
        self.start_time = timer() if auto_start else None
        self.end_time = None
        self.sub_timers = []

    def start(self):
        if self.start_time is not None:
            raise ValueError(f"Timer {self.name} has already been started.")
        self.start_time = timer()

    def stop(self, stop_subtimers=True):
        if stop_subtimers:
            for sub_timer in self.sub_timers:
                sub_timer.stop()

        # if the timer has already been stopped, do nothing
        self.end_time = self.end_time or timer()

    def create_subtimer(self, name, auto_start=True, stop_previous=True):
        for subtimer in self.sub_timers:
            if subtimer.name == name:
                raise ValueError(f"Timer with name {name} already exists.")

        if stop_previous and self.sub_timers:
            self.sub_timers[-1].stop()

        sub_timer = NamedTimer(name, auto_start=auto_start)
        self.sub_timers.append(sub_timer)
        return sub_timer

    def __getitem__(self, name):
        for subtimer in self.sub_timers:
            if subtimer.name == name:
                return subtimer
        raise ValueError(f"Timer with name {name} does not exist.")

    def elapsed(self) -> float:
        if self.start_time is None:
            raise ValueError(f"Timer {self.name} has not been started")

        end_time = self.end_time if self.end_time is not None else timer()

        return end_time - self.start_time

    def report(self, include_subtimers=True) -> str:
        sub_reports_str = ""

        if include_subtimers:
            sub_reports = [
                f"{timer.name}: {timer.elapsed():.2f}s" for timer in self.sub_timers
            ]
            sub_reports_str = f" ({', '.join(sub_reports)})" if sub_reports else ""

        return f"{self.name}: {self.elapsed():.2f}s{sub_reports_str}"

    def __str__(self):
        return self.report()

    def __repr__(self):
        return (
            f"NamedTimer(name={self.name}, start_time={self.start_time}, "
            f"end_time={self.end_time}, sub_timers={self.sub_timers})"
        )


def format_size(num_bytes: int) -> str:
    """
    Returns a human-readable string for a number of bytes
    Automatically chooses a relevant size unit (G, M, K, B)

    e.g.:
        1234567890 -> 1.15G
        123456789 -> 117.7M
        123456 -> 120.5K
        123 -> 123B
    """
    if num_bytes >= 1024 * 1024 * 1024:
        return f"{num_bytes / (1024 * 1024 * 1024):.2f}GB"
    elif num_bytes >= 1024 * 1024:
        return f"{num_bytes / (1024 * 1024):.1f}MB"
    elif num_bytes >= 1024:
        return f"{num_bytes / 1024:.1f}KB"
    else:
        return f"{num_bytes}B"


def format_time(seconds: float) -> str:
    """
    Returns a pretty string for an elapsed time in seconds.
    Automatically chooses a relevant time unit (h, m, s, ms, µs, ns)

    Examples:
        3602.13 -> 1h00m02s
        62.003 -> 1m02s
        1.000000001 -> 1.000s
        0.123456789 -> 123.457ms
        0.000000001 -> 1.000ns
    """
    if seconds >= 3600:
        # 1 hour or more
        hours = int(seconds / 3600)
        minutes = int((seconds - (3600 * hours)) / 60)
        seconds_rounded = int(seconds - (3600 * hours) - (60 * minutes))
        return f"{hours}h{minutes:02}m{seconds_rounded:02}s"
    elif seconds >= 60:
        # 1 minute or more
        minutes = int(seconds / 60)
        seconds_rounded = int(seconds - (60 * minutes))
        return f"{minutes}m{seconds_rounded:02}s"
    elif seconds >= 1:
        # 1 second or more
        return f"{seconds:.3f}s"
    elif seconds >= 1e-3:
        # 1 millisecond or more
        return f"{seconds * 1e3:.3f}ms"
    elif seconds >= 1e-6:
        # 1 microsecond or more
        return f"{seconds * 1e6:.3f}µs"
    else:
        # Otherwise, display in nanoseconds
        return f"{seconds * 1e9:.3f}ns"


def parse_time(arg: int | float | str, default_unit: str | None = "s") -> float:
    """
    Parse a time string into a number of seconds, with an optional unit suffix.

    Examples:
        "200ms" -> 0.2
        "5s" -> 5.0
        "2m" -> 120.0
        "1h" -> 3600.0

    Note: does not support combined units like "1h00m02s" (like `format_time` produces)
    """

    if default_unit and default_unit not in ["ms", "s", "m", "h"]:
        raise ValueError(f"Invalid time unit: {default_unit}")

    if isinstance(arg, str):
        if arg.endswith("ms"):
            return float(arg[:-2]) / 1000
        elif arg.endswith("s"):
            return float(arg[:-1])
        elif arg.endswith("m"):
            return float(arg[:-1]) * 60
        elif arg.endswith("h"):
            return float(arg[:-1]) * 3600
        elif arg == "0":
            return 0.0
        else:
            if not default_unit:
                raise ValueError(f"Could not infer time unit from {arg}")
            return parse_time(arg + default_unit, default_unit=None)
    elif isinstance(arg, int | float):
        if not default_unit:
            raise ValueError(f"Could not infer time unit from {arg}")
        return parse_time(str(arg) + default_unit, default_unit=None)
    else:
        raise ValueError(f"Invalid time argument: {arg}")


class timed_block:
    def __init__(self, label="Block"):
        self.label = label

    def __enter__(self):
        self.start = timer()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        end = timer()
        elapsed = end - self.start
        print(f"{self.label} took {format_time(elapsed)}")


def timed(label=None):
    """
    A decorator that measures and prints the execution time of a function.

    Args:
        label (str, optional): Custom label for the timing output. If None, the function name will be used.

    Returns:
        callable: The wrapped function with timing functionality.
    """

    def decorator(func):
        def wrapper(*args, **kwargs):
            # Use function name if no label is provided
            function_label = label if label is not None else func.__name__

            with timed_block(function_label):
                result = func(*args, **kwargs)

            return result

        return wrapper

    return decorator


dict_of_unsupported_cheatcodes = {
    0x23361207: "expectCall(address,uint256,uint64,bytes)",
    0x97624631: "assertEq(bytes,bytes)",
    0x743E4CB7: "accessList((address,bytes32[])[])",
    0x240F839D: "assertApproxEqAbs(int256,int256,uint256)",
    0x8289E621: "assertApproxEqAbs(int256,int256,uint256,string)",
    0x16D207C6: "assertApproxEqAbs(uint256,uint256,uint256)",
    0xF710B062: "assertApproxEqAbs(uint256,uint256,uint256,string)",
    0x3D5BC8BC: "assertApproxEqAbsDecimal(int256,int256,uint256,uint256)",
    0x6A5066D4: "assertApproxEqAbsDecimal(int256,int256,uint256,uint256,string)",
    0x045C55CE: "assertApproxEqAbsDecimal(uint256,uint256,uint256,uint256)",
    0x60429EB2: "assertApproxEqAbsDecimal(uint256,uint256,uint256,uint256,string)",
    0xFEA2D14F: "assertApproxEqRel(int256,int256,uint256)",
    0xEF277D72: "assertApproxEqRel(int256,int256,uint256,string)",
    0x8CF25EF4: "assertApproxEqRel(uint256,uint256,uint256)",
    0x1ECB7D33: "assertApproxEqRel(uint256,uint256,uint256,string)",
    0xABBF21CC: "assertApproxEqRelDecimal(int256,int256,uint256,uint256)",
    0xFCCC11C4: "assertApproxEqRelDecimal(int256,int256,uint256,uint256,string)",
    0x21ED2977: "assertApproxEqRelDecimal(uint256,uint256,uint256,uint256)",
    0x82D6C8FD: "assertApproxEqRelDecimal(uint256,uint256,uint256,uint256,string)",
    0x515361F6: "assertEq(address,address)",
    0x2F2769D1: "assertEq(address,address,string)",
    0x3868AC34: "assertEq(address[],address[])",
    0x3E9173C5: "assertEq(address[],address[],string)",
    0xF7FE3477: "assertEq(bool,bool)",
    0x4DB19E7E: "assertEq(bool,bool,string)",
    0x707DF785: "assertEq(bool[],bool[])",
    0xE48A8F8D: "assertEq(bool[],bool[],string)",
    0xE24FED00: "assertEq(bytes,bytes,string)",
    0x7C84C69B: "assertEq(bytes32,bytes32)",
    0xC1FA1ED0: "assertEq(bytes32,bytes32,string)",
    0x0CC9EE84: "assertEq(bytes32[],bytes32[])",
    0xE03E9177: "assertEq(bytes32[],bytes32[],string)",
    0xE5FB9B4A: "assertEq(bytes[],bytes[])",
    0xF413F0B6: "assertEq(bytes[],bytes[],string)",
    0xFE74F05B: "assertEq(int256,int256)",
    0x714A2F13: "assertEq(int256,int256,string)",
    0x711043AC: "assertEq(int256[],int256[])",
    0x191F1B30: "assertEq(int256[],int256[],string)",
    0xF320D963: "assertEq(string,string)",
    0x36F656D8: "assertEq(string,string,string)",
    0xCF1C049C: "assertEq(string[],string[])",
    0xEFF6B27D: "assertEq(string[],string[],string)",
    0x98296C54: "assertEq(uint256,uint256)",
    0x88B44C85: "assertEq(uint256,uint256,string)",
    0x975D5A12: "assertEq(uint256[],uint256[])",
    0x5D18C73A: "assertEq(uint256[],uint256[],string)",
    0x48016C04: "assertEqDecimal(int256,int256,uint256)",
    0x7E77B0C5: "assertEqDecimal(int256,int256,uint256,string)",
    0x27AF7D9C: "assertEqDecimal(uint256,uint256,uint256)",
    0xD0CBBDEF: "assertEqDecimal(uint256,uint256,uint256,string)",
    0xA5982885: "assertFalse(bool)",
    0x7BA04809: "assertFalse(bool,string)",
    0x0A30B771: "assertGe(int256,int256)",
    0xA84328DD: "assertGe(int256,int256,string)",
    0xA8D4D1D9: "assertGe(uint256,uint256)",
    0xE25242C0: "assertGe(uint256,uint256,string)",
    0xDC28C0F1: "assertGeDecimal(int256,int256,uint256)",
    0x5DF93C9B: "assertGeDecimal(int256,int256,uint256,string)",
    0x3D1FE08A: "assertGeDecimal(uint256,uint256,uint256)",
    0x8BFF9133: "assertGeDecimal(uint256,uint256,uint256,string)",
    0x5A362D45: "assertGt(int256,int256)",
    0xF8D33B9B: "assertGt(int256,int256,string)",
    0xDB07FCD2: "assertGt(uint256,uint256)",
    0xD9A3C4D2: "assertGt(uint256,uint256,string)",
    0x78611F0E: "assertGtDecimal(int256,int256,uint256)",
    0x04A5C7AB: "assertGtDecimal(int256,int256,uint256,string)",
    0xECCD2437: "assertGtDecimal(uint256,uint256,uint256)",
    0x64949A8D: "assertGtDecimal(uint256,uint256,uint256,string)",
    0x95FD154E: "assertLe(int256,int256)",
    0x4DFE692C: "assertLe(int256,int256,string)",
    0x8466F415: "assertLe(uint256,uint256)",
    0xD17D4B0D: "assertLe(uint256,uint256,string)",
    0x11D1364A: "assertLeDecimal(int256,int256,uint256)",
    0xAA5CF788: "assertLeDecimal(int256,int256,uint256,string)",
    0xC304AAB7: "assertLeDecimal(uint256,uint256,uint256)",
    0x7FEFBBE0: "assertLeDecimal(uint256,uint256,uint256,string)",
    0x3E914080: "assertLt(int256,int256)",
    0x9FF531E3: "assertLt(int256,int256,string)",
    0xB12FC005: "assertLt(uint256,uint256)",
    0x65D5C135: "assertLt(uint256,uint256,string)",
    0xDBE8D88B: "assertLtDecimal(int256,int256,uint256)",
    0x40F0B4E0: "assertLtDecimal(int256,int256,uint256,string)",
    0x2077337E: "assertLtDecimal(uint256,uint256,uint256)",
    0xA972D037: "assertLtDecimal(uint256,uint256,uint256,string)",
    0xB12E1694: "assertNotEq(address,address)",
    0x8775A591: "assertNotEq(address,address,string)",
    0x46D0B252: "assertNotEq(address[],address[])",
    0x72C7E0B5: "assertNotEq(address[],address[],string)",
    0x236E4D66: "assertNotEq(bool,bool)",
    0x1091A261: "assertNotEq(bool,bool,string)",
    0x286FAFEA: "assertNotEq(bool[],bool[])",
    0x62C6F9FB: "assertNotEq(bool[],bool[],string)",
    0x3CF78E28: "assertNotEq(bytes,bytes)",
    0x9507540E: "assertNotEq(bytes,bytes,string)",
    0x898E83FC: "assertNotEq(bytes32,bytes32)",
    0xB2332F51: "assertNotEq(bytes32,bytes32,string)",
    0x0603EA68: "assertNotEq(bytes32[],bytes32[])",
    0xB873634C: "assertNotEq(bytes32[],bytes32[],string)",
    0xEDECD035: "assertNotEq(bytes[],bytes[])",
    0x1DCD1F68: "assertNotEq(bytes[],bytes[],string)",
    0xF4C004E3: "assertNotEq(int256,int256)",
    0x4724C5B9: "assertNotEq(int256,int256,string)",
    0x0B72F4EF: "assertNotEq(int256[],int256[])",
    0xD3977322: "assertNotEq(int256[],int256[],string)",
    0x6A8237B3: "assertNotEq(string,string)",
    0x78BDCEA7: "assertNotEq(string,string,string)",
    0xBDFACBE8: "assertNotEq(string[],string[])",
    0xB67187F3: "assertNotEq(string[],string[],string)",
    0xB7909320: "assertNotEq(uint256,uint256)",
    0x98F9BDBD: "assertNotEq(uint256,uint256,string)",
    0x56F29CBA: "assertNotEq(uint256[],uint256[])",
    0x9A7FBD8F: "assertNotEq(uint256[],uint256[],string)",
    0x14E75680: "assertNotEqDecimal(int256,int256,uint256)",
    0x33949F0B: "assertNotEqDecimal(int256,int256,uint256,string)",
    0x669EFCA7: "assertNotEqDecimal(uint256,uint256,uint256)",
    0xF5A55558: "assertNotEqDecimal(uint256,uint256,uint256,string)",
    0x0C9FD581: "assertTrue(bool)",
    0xA34EDC03: "assertTrue(bool,string)",
    0xD8591EEB: "assumeNoRevert((address,bool,bytes))",
    0x8A4592CC: "assumeNoRevert((address,bool,bytes)[])",
    0x10CB385C: "attachBlob(bytes)",
    0x6D315D7E: "blobBaseFee(uint256)",
    0x129DE7EB: "blobhashes(bytes32[])",
    0x8C0C72E0: "broadcastRawTransaction(bytes)",
    0x533D61C9: "cloneAccount(address,address)",
    0x890C283B: "computeCreate2Address(bytes32,bytes32)",
    0xD323826A: "computeCreate2Address(bytes32,bytes32,address)",
    0x74637A7A: "computeCreateAddress(address,uint256)",
    0x3FB18AEC: "contains(string,string)",
    0x40FF9F21: "cool(address)",
    0x8C78E654: "coolSlot(address,bytes32)",
    0xA54A87D8: "copyFile(string,string)",
    0x168B64D3: "createDir(string,bool)",
    0xA6368557: "deleteSnapshot(uint256)",
    0x421AE469: "deleteSnapshots()",
    0x9A8325A0: "deployCode(string)",
    0x29CE9DDE: "deployCode(string,bytes)",
    0x016155BF: "deployCode(string,bytes,bytes32)",
    0xFF5D64E4: "deployCode(string,bytes,uint256)",
    0x3AA773EA: "deployCode(string,bytes,uint256,bytes32)",
    0x17AB1D79: "deployCode(string,bytes32)",
    0x0AF6A701: "deployCode(string,uint256)",
    0x002CB687: "deployCode(string,uint256,bytes32)",
    0x29233B1F: "deriveKey(string,string,uint32,string)",
    0x32C8176D: "deriveKey(string,uint32,string)",
    0x709ECD3F: "dumpState(string)",
    0x8C374C65: "ensNamehash(string)",
    0x35E1349B: "eth_getLogs(uint256,uint256,address,bytes32[])",
    0x65B7B7CC: "expectCall(address,uint256,uint64,bytes,uint64)",
    0x08E4E116: "expectCallMinGas(address,uint256,uint64,bytes)",
    0xE13A1834: "expectCallMinGas(address,uint256,uint64,bytes,uint64)",
    0x73CDCE36: "expectCreate(bytes,address)",
    0xEA54A472: "expectCreate2(bytes,address)",
    0xB43AECE3: "expectEmit(address,uint64)",
    0xC339D02C: "expectEmit(bool,bool,bool,bool,address,uint64)",
    0x5E1D1C33: "expectEmit(bool,bool,bool,bool,uint64)",
    0x4C74A335: "expectEmit(uint64)",
    0x2E5F270C: "expectEmitAnonymous()",
    0x6FC68705: "expectEmitAnonymous(address)",
    0xC948DB5E: "expectEmitAnonymous(bool,bool,bool,bool,bool)",
    0x71C95899: "expectEmitAnonymous(bool,bool,bool,bool,bool,address)",
    0x6D016688: "expectSafeMemory(uint64,uint64)",
    0x05838BF4: "expectSafeMemoryCall(uint64,uint64)",
    0x6248BE1F: "foundryVersionAtLeast(string)",
    0xCA7B0A09: "foundryVersionCmp(string)",
    0xAF368A08: "fsMetadata(string)",
    0xEB74848C: "getArtifactPathByCode(bytes)",
    0x6D853BA5: "getArtifactPathByDeployedCode(bytes)",
    0x1F6D6EF7: "getBlobBaseFee()",
    0xF56FF18B: "getBlobhashes()",
    0x3DC90CB3: "getBroadcast(string,uint64,uint8)",
    0xF2FA4A26: "getBroadcasts(string,uint64)",
    0xF7AFE919: "getBroadcasts(string,uint64,uint8)",
    0x4CC1C2BB: "getChain(string)",
    0xB6791AD4: "getChain(uint256)",
    0xA8091D97: "getDeployment(string)",
    0x0DEBD5D6: "getDeployment(string,uint64)",
    0x74E133DD: "getDeployments(string,uint64)",
    0xEA991BB5: "getFoundryVersion()",
    0x876E24E6: "getMappingKeyAndParentOf(address,bytes32)",
    0x2F2FD63F: "getMappingLength(address,bytes32)",
    0xEBC73AB4: "getMappingSlotAt(address,bytes32,uint256)",
    0x80DF01CC: "getStateDiff()",
    0xF54FE009: "getStateDiffJson()",
    0xDB7A4605: "getWallets()",
    0x8A0807B7: "indexOf(string,string)",
    0x838653C7: "interceptInitcode()",
    0x2B589B28: "lastCallGas()",
    0xB3A056D7: "loadAllocs(string)",
    0x08E0C537: "mockCall(address,bytes4,bytes)",
    0xE7B36A3D: "mockCall(address,uint256,bytes4,bytes)",
    0x2DFBA5DF: "mockCallRevert(address,bytes4,bytes)",
    0x596C8F04: "mockCallRevert(address,uint256,bytes4,bytes)",
    0x238AD778: "noAccessList()",
    0x1E19E657: "parseJsonAddress(string,string)",
    0x2FCE7883: "parseJsonAddressArray(string,string)",
    0x9F86DC91: "parseJsonBool(string,string)",
    0x91F3B94F: "parseJsonBoolArray(string,string)",
    0xFD921BE8: "parseJsonBytes(string,string)",
    0x1777E59D: "parseJsonBytes32(string,string)",
    0x91C75BC3: "parseJsonBytes32Array(string,string)",
    0x6631AA99: "parseJsonBytesArray(string,string)",
    0x7B048CCD: "parseJsonInt(string,string)",
    0x9983C28A: "parseJsonIntArray(string,string)",
    0x49C4FAC8: "parseJsonString(string,string)",
    0x498FDCF4: "parseJsonStringArray(string,string)",
    0xA9DA313B: "parseJsonType(string,string)",
    0xE3F5AE33: "parseJsonType(string,string,string)",
    0x0175D535: "parseJsonTypeArray(string,string,string)",
    0xADDDE2B6: "parseJsonUint(string,string)",
    0x522074AB: "parseJsonUintArray(string,string)",
    0x65E7C844: "parseTomlAddress(string,string)",
    0x65C428E7: "parseTomlAddressArray(string,string)",
    0xD30DCED6: "parseTomlBool(string,string)",
    0x127CFE9A: "parseTomlBoolArray(string,string)",
    0xD77BFDB9: "parseTomlBytes(string,string)",
    0x8E214810: "parseTomlBytes32(string,string)",
    0x3E716F81: "parseTomlBytes32Array(string,string)",
    0xB197C247: "parseTomlBytesArray(string,string)",
    0xC1350739: "parseTomlInt(string,string)",
    0xD3522AE6: "parseTomlIntArray(string,string)",
    0x8BB8DD43: "parseTomlString(string,string)",
    0x9F629281: "parseTomlStringArray(string,string)",
    0x47FA5E11: "parseTomlType(string,string)",
    0xF9FA5CDB: "parseTomlType(string,string,string)",
    0x49BE3743: "parseTomlTypeArray(string,string,string)",
    0xCC7B0487: "parseTomlUint(string,string)",
    0xB5DF27C8: "parseTomlUintArray(string,string)",
    0xC94D1F90: "pauseTracing()",
    0x9CB1C0D4: "prevrandao(uint256)",
    0x62EE05F4: "promptAddress(string)",
    0x652FD489: "promptUint(string)",
    0xC453949E: "publicKeyP256(uint256)",
    0x1497876C: "readDir(string,uint64)",
    0x8102D70D: "readDir(string,uint64,bool)",
    0xF8D58EAF: "rememberKeys(string,string,string,uint32)",
    0x97CB9189: "rememberKeys(string,string,uint32)",
    0x45C62011: "removeDir(string,bool)",
    0xE00AD03E: "replace(string,string,string)",
    0x1C72346D: "resetNonce(address)",
    0x72A09CCB: "resumeTracing()",
    0x44D7F0A4: "revertTo(uint256)",
    0x03E0ACA9: "revertToAndDelete(uint256)",
    0x0199A220: "rpc(string,string,string)",
    0x9D2AD72A: "rpcUrlStructs()",
    0x6D4F96A6: "serializeJsonType(string,bytes)",
    0x6F93BCCB: "serializeJsonType(string,string,string,bytes)",
    0xAE5A2AE8: "serializeUintToHex(string,string,uint256)",
    0xD3EC2A0B: "setArbitraryStorage(address,bool)",
    0x5314B54A: "setBlockhash(uint256,bytes32)",
    0x9B67B21C: "setNonceUnsafe(address,uint64)",
    0x54F1469C: "shuffle(uint256[])",
    0x8C1AA205: "sign(address,bytes32)",
    0x799CD333: "sign(bytes32)",
    0xCDE3E5BE: "signAndAttachDelegation(address,uint256,uint64)",
    0x3D0E292F: "signCompact((address,uint256,uint256,uint256),bytes32)",
    0x8E2F97BF: "signCompact(address,bytes32)",
    0xA282DC4B: "signCompact(bytes32)",
    0xCC2A781F: "signCompact(uint256,bytes32)",
    0xCEBA2EC3: "signDelegation(address,uint256,uint64)",
    0x83211B40: "signP256(uint256,bytes32)",
    0xC42A80A7: "skip(bool,string)",
    0x9711715A: "snapshot()",
    0x9EC8B026: "sort(uint256[])",
    0x8BB75533: "split(string,string)",
    0x419C8832: "startDebugTraceRecording()",
    0x3E9705C0: "startMappingRecording()",
    0xCED398A2: "stopAndReturnDebugTraceRecording()",
    0x0956441B: "stopExpectSafeMemory()",
    0x0D4AAE9B: "stopMappingRecording()",
    0xA5CBFE65: "toBase64(bytes)",
    0x3F8BE2C8: "toBase64(string)",
    0xC8BD0E4A: "toBase64URL(bytes)",
    0xAE3165B3: "toBase64URL(string)",
    0x50BB0884: "toLowercase(string)",
    0x074AE3D7: "toUppercase(string)",
    0xB2DAD155: "trim(string)",
    0xF45C1CE7: "tryFfi(string[])",
    0xB23184CF: "warmSlot(address,bytes32)",
    0x1F21FC80: "writeFileBinary(string,bytes)",
    0xBD6AF434: "expectCall(address,bytes)",
    0xC1ADBBFF: "expectCall(address,bytes,uint64)",
    0xF30C7BA3: "expectCall(address,uint256,bytes)",
    0xA2B1A1AE: "expectCall(address,uint256,bytes,uint64)",
    0x440ED10D: "expectEmit()",
    0x86B9620D: "expectEmit(address)",
    0x491CC7C2: "expectEmit(bool,bool,bool,bool)",
    0x81BAD6F3: "expectEmit(bool,bool,bool,bool,address)",
    0x11FB5B9C: "expectPartialRevert(bytes4)",
    0x51AA008A: "expectPartialRevert(bytes4,address)",
    0xF4844814: "expectRevert()",
    0xD814F38A: "expectRevert(address)",
    0x1FF5F952: "expectRevert(address,uint64)",
    0xF28DCEB3: "expectRevert(bytes)",
    0x61EBCF12: "expectRevert(bytes,address)",
    0xD345FB1F: "expectRevert(bytes,address,uint64)",
    0x4994C273: "expectRevert(bytes,uint64)",
    0xC31EB0E0: "expectRevert(bytes4)",
    0x260BC5DE: "expectRevert(bytes4,address)",
    0xB0762D73: "expectRevert(bytes4,address,uint64)",
    0xE45CA72D: "expectRevert(bytes4,uint64)",
    0x4EE38244: "expectRevert(uint64)",
    0x65BC9481: "accesses(address)",
    0xAFC98040: "broadcast()",
    0xE6962CDB: "broadcast(address)",
    0xF67A965B: "broadcast(uint256)",
    0x3FDF4E15: "clearMockedCalls()",
    0x08D6B37A: "deleteStateSnapshot(uint256)",
    0xE0933C74: "deleteStateSnapshots()",
    0x796B89B9: "getBlockTimestamp()",
    0xA5748AAD: "getNonce((address,uint256,uint256,uint256))",
    0x2D0335AB: "getNonce(address)",
    0x191553A4: "getRecordedLogs()",
    0x64AF255D: "isContext(uint8)",
    0xB96213E4: "mockCall(address,bytes,bytes)",
    0x81409B91: "mockCall(address,uint256,bytes,bytes)",
    0xDBAAD147: "mockCallRevert(address,bytes,bytes)",
    0xD23CD037: "mockCallRevert(address,uint256,bytes,bytes)",
    0x5C5C3DE9: "mockCalls(address,bytes,bytes[])",
    0x08BCBAE1: "mockCalls(address,uint256,bytes,bytes[])",
    0xADF84D21: "mockFunction(address,address,bytes)",
    0xD1A5B36F: "pauseGasMetering()",
    0x7D73D042: "prank(address,address,bool)",
    0xA7F8BF5C: "prank(address,bool)",
    0x3B925549: "prevrandao(bytes32)",
    0x4AD0BAC9: "readCallers()",
    0x266CF109: "record()",
    0x41AF2F52: "recordLogs()",
    0xBE367DD3: "resetGasMetering()",
    0x2BCD50E0: "resumeGasMetering()",
    0xC2527405: "revertToState(uint256)",
    0x3A1985DC: "revertToStateAndDelete(uint256)",
    0xF8E18B57: "setNonce(address,uint64)",
    0xDD9FCA12: "snapshotGasLastCall(string)",
    0x200C6772: "snapshotGasLastCall(string,string)",
    0x6D2B27D8: "snapshotValue(string,string,uint256)",
    0x51DB805A: "snapshotValue(string,uint256)",
    0x7FB5297F: "startBroadcast()",
    0x7FEC2A8D: "startBroadcast(address)",
    0xCE817D47: "startBroadcast(uint256)",
    0x4EB859B5: "startPrank(address,address,bool)",
    0x1CC0B435: "startPrank(address,bool)",
    0x3CAD9D7B: "startSnapshotGas(string)",
    0x6CD0CC53: "startSnapshotGas(string,string)",
    0xCF22E3C9: "startStateDiffRecording()",
    0xAA5CF90E: "stopAndReturnStateDiff()",
    0x76EADD36: "stopBroadcast()",
    0xF6402EDA: "stopSnapshotGas()",
    0x773B2805: "stopSnapshotGas(string)",
    0x0C9DB707: "stopSnapshotGas(string,string)",
    0x48F50C0F: "txGasPrice(uint256)",
    0x285B366A: "assumeNoRevert()",
    0x98680034: "createSelectFork(string)",
    0x2F103F22: "activeFork()",
    0xEA060291: "allowCheatcodes(address)",
    0x31BA3498: "createFork(string)",
    0x7CA29682: "createFork(string,bytes32)",
    0x6BA3BA2B: "createFork(string,uint256)",
    0x84D52B7A: "createSelectFork(string,bytes32)",
    0x71EE464D: "createSelectFork(string,uint256)",
    0xD92D8EFD: "isPersistent(address)",
    0x57E22DDE: "makePersistent(address)",
    0x4074E0A8: "makePersistent(address,address)",
    0xEFB77A75: "makePersistent(address,address,address)",
    0x1D9E269E: "makePersistent(address[])",
    0x997A0222: "revokePersistent(address)",
    0x3CE969E6: "revokePersistent(address[])",
    0x0F29772B: "rollFork(bytes32)",
    0xD9BBF3A1: "rollFork(uint256)",
    0xF2830F7B: "rollFork(uint256,bytes32)",
    0xD74C83A4: "rollFork(uint256,uint256)",
    0x9EBF6827: "selectFork(uint256)",
    0xBE646DA1: "transact(bytes32)",
    0x4D8ABC4B: "transact(uint256,bytes32)",
    0x3EBF73B4: "getDeployedCode(string)",
    0x528A683C: "keyExists(string,string)",
    0xDB4235F6: "keyExistsJson(string,string)",
    0x600903AD: "keyExistsToml(string,string)",
    0x6A82600A: "parseJson(string)",
    0x85940EF1: "parseJson(string,string)",
    0x213E4198: "parseJsonKeys(string,string)",
    0x592151F0: "parseToml(string)",
    0x37736E08: "parseToml(string,string)",
    0x812A44B2: "parseTomlKeys(string,string)",
    0xD930A0E6: "projectRoot()",
    0x47EAF474: "prompt(string)",
    0x1E279D41: "promptSecret(string)",
    0x69CA02B7: "promptSecretUint(string)",
    0x972C6062: "serializeAddress(string,string,address)",
    0x1E356E1A: "serializeAddress(string,string,address[])",
    0xAC22E971: "serializeBool(string,string,bool)",
    0x92925AA1: "serializeBool(string,string,bool[])",
    0xF21D52C7: "serializeBytes(string,string,bytes)",
    0x9884B232: "serializeBytes(string,string,bytes[])",
    0x2D812B44: "serializeBytes32(string,string,bytes32)",
    0x201E43E2: "serializeBytes32(string,string,bytes32[])",
    0x3F33DB60: "serializeInt(string,string,int256)",
    0x7676E127: "serializeInt(string,string,int256[])",
    0x9B3358B0: "serializeJson(string,string)",
    0x88DA6D35: "serializeString(string,string,string)",
    0x561CD6F3: "serializeString(string,string,string[])",
    0x129E9002: "serializeUint(string,string,uint256)",
    0xFEE9A469: "serializeUint(string,string,uint256[])",
    0x3D5923EE: "setEnv(string,string)",
    0xFA9D8713: "sleep(uint256)",
    0x625387DC: "unixTime()",
    0xE23CD19F: "writeJson(string,string)",
    0x35D6AD46: "writeJson(string,string,string)",
    0xC0865BA7: "writeToml(string,string)",
    0x51AC6A33: "writeToml(string,string,string)",
    0x14AE3519: "attachDelegation((uint8,bytes32,bytes32,uint64,address))",
    0xB25C5A25: "sign((address,uint256,uint256,uint256),bytes32)",
    0xC7FA7288: "signAndAttachDelegation(address,uint256)",
    0x5B593C7B: "signDelegation(address,uint256)",
    0x22100064: "rememberKey(uint256)",
    0xF0259E92: "breakpoint(string)",
    0xF7D39A8D: "breakpoint(string,bool)",
    0x203DAC0D: "copyStorage(address,address)",
    0x7404F1D2: "createWallet(string)",
    0x7A675BB6: "createWallet(uint256)",
    0xED7C5462: "createWallet(uint256,string)",
    0x6BCB2C1B: "deriveKey(string,string,uint32)",
    0x6229498B: "deriveKey(string,uint32)",
    0x28A249B0: "getLabel(address)",
    0xC6CE059D: "parseAddress(string)",
    0x974EF924: "parseBool(string)",
    0x8F5D232D: "parseBytes(string)",
    0x087E6E81: "parseBytes32(string)",
    0x42346C5E: "parseInt(string)",
    0xFA91454D: "parseUint(string)",
    0xDD82D13E: "skip(bool)",
    0x56CA623E: "toString(address)",
    0x71DCE7DA: "toString(bool)",
    0x71AAD10D: "toString(bytes)",
    0xB11A19E8: "toString(bytes32)",
    0xA322C40E: "toString(int256)",
    0x6900A3AE: "toString(uint256)",
    0x1206C8A8: "rpc(string,string)",
    0x975A6CE9: "rpcUrl(string)",
    0xA85A8418: "rpcUrls()",
    0x48C3241F: "closeFile(string)",
    0x261A323E: "exists(string)",
    0x7D15D019: "isDir(string)",
    0xE0EB04D4: "isFile(string)",
    0xC4BC59E0: "readDir(string)",
    0x60F9BB11: "readFile(string)",
    0x16ED7BC4: "readFileBinary(string)",
    0x70F55728: "readLine(string)",
    0x9F5684A2: "readLink(string)",
    0xF1AFE04D: "removeFile(string)",
    0x897E0A97: "writeFile(string,string)",
    0x619D897F: "writeLine(string,string)",
}
