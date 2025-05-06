# SPDX-License-Identifier: AGPL-3.0

import math
import re
import uuid
from functools import partial
from timeit import default_timer as timer
from typing import Any

from z3 import (
    Z3_OP_BADD,
    Z3_OP_CONCAT,
    Z3_OP_ULEQ,
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

from .bitvec import HalmosBitVec as BV
from .bitvec import HalmosBool as Bool
from .exceptions import HalmosException, NotConcreteError
from .hashes import keccak256_256, keccak256_512
from .logs import warn
from .mapper import Mapper

# order of the secp256k1 curve
secp256k1n = (
    115792089237316195423570985008687907852837564279074904382605163141518161494337
)

Byte = int | BitVecRef | BV  # uint8
Bytes4 = int | BitVecRef | BV  # uint32
Address = int | BitVecRef | BV  # uint160
Word = int | BitVecRef | BV  # uint256
Bytes = "bytes | BitVecRef | ByteVec"  # arbitrary-length sequence of bytes


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


def int256(x: BitVecRef) -> BitVecRef:
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


def create_solver(logic="QF_AUFBV", ctx=None, timeout=0, max_memory=0):
    # QF_AUFBV: quantifier-free bitvector + array theory: https://smtlib.cs.uiowa.edu/logics.shtml
    solver = SolverFor(logic, ctx=ctx)

    # set timeout
    solver.set(timeout=timeout)

    # set memory limit
    if max_memory > 0:
        solver.set(max_memory=max_memory)

    return solver


def extract_bytes32_array_argument(data: Bytes, arg_idx: int):
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


def extract_string_argument(data: Bytes, arg_idx: int):
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


def con_addr(n: int) -> BitVecRef:
    if n >= 2**160:
        raise ValueError(n)
    return BitVecVal(n, 160)


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

    def __getitem__(self, k: int) -> tuple[int, int]:
        """Get the value and offset delta for a key.

        Args:
            k: The integer key to look up

        Returns:
            A tuple of (value, delta) where:
            - value is the stored value (or None if not found)
            - delta is the difference between the requested offset and stored offset
              Note: delta can be negative, e.g., when computing slot(a[n-1]) which is `(keccak(slot(a)) - 1) + n`
        """
        (v, offset) = self._map.get(k >> self._offset_bits, (None, None))
        if v is None:
            return (None, None)
        delta = (k & self._mask) - offset
        return (v, delta)

    def __setitem__(self, k: int, v: Any):
        """Store a value with its offset.

        Args:
            k: The integer key to store
            v: The value to store
        """
        self._map[k >> self._offset_bits] = (v, k & self._mask)

    def copy(self) -> "OffsetMap":
        """Create a deep copy of this OffsetMap.

        Returns:
            A new OffsetMap instance with the same offset_bits and copied mapping.
        """
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
