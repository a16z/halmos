# SPDX-License-Identifier: AGPL-3.0

import json
import math
import re

from copy import deepcopy
from collections import defaultdict
from dataclasses import dataclass, field
from functools import reduce
from subprocess import Popen, PIPE
from typing import (
    Any,
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
from z3 import *

from .cheatcodes import halmos_cheat_code, hevm_cheat_code, console, Prank
from .exceptions import *
from .utils import (
    create_solver,
    EVM,
    sha3_inv,
    restore_precomputed_hashes,
    str_opcode,
    assert_address,
    assert_uint256,
    con_addr,
    bv_value_to_bytes,
    hexify,
    color_info,
)
from .warnings import (
    warn,
    UNSUPPORTED_OPCODE,
    LIBRARY_PLACEHOLDER,
    UNINTERPRETED_UNKNOWN_CALLS,
    INTERNAL_ERROR,
)

Word = Any  # z3 expression (including constants)
Byte = Any  # z3 expression (including constants)
Bytes = Any  # z3 expression (including constants)
Address = BitVecRef  # 160-bitvector

Steps = Dict[int, Dict[str, Any]]  # execution tree

EMPTY_BYTES = b""
MAX_CALL_DEPTH = 1024


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

# symbolic states
# calldataload(index)
f_calldataload = Function("calldataload", BitVecSort256, BitVecSort256)
# calldatasize()
f_calldatasize = Function("calldatasize", BitVecSort256)
# extcodesize(target address)
f_extcodesize = Function("extcodesize", BitVecSort160, BitVecSort256)
# extcodehash(target address)
f_extcodehash = Function("extcodehash", BitVecSort160, BitVecSort256)
# blockhash(block number)
f_blockhash = Function("blockhash", BitVecSort256, BitVecSort256)
# gas(cnt)
f_gas = Function("gas", BitVecSort256, BitVecSort256)
# gasprice()
f_gasprice = Function("gasprice", BitVecSort256)
# origin()
f_origin = Function("origin", BitVecSort160)

# uninterpreted arithmetic
f_div = Function("evm_bvudiv", BitVecSort256, BitVecSort256, BitVecSort256)
f_mod = {
    256: Function("evm_bvurem", BitVecSort256, BitVecSort256, BitVecSort256),
    264: Function("evm_bvurem_264", BitVecSort264, BitVecSort264, BitVecSort264),
    512: Function("evm_bvurem_512", BitVecSort512, BitVecSort512, BitVecSort512),
}
f_sdiv = Function("evm_bvsdiv", BitVecSort256, BitVecSort256, BitVecSort256)
f_smod = Function("evm_bvsrem", BitVecSort256, BitVecSort256, BitVecSort256)
f_exp = Function("evm_exp", BitVecSort256, BitVecSort256, BitVecSort256)

magic_address: int = 0xAAAA0000

create2_magic_address: int = 0xBBBB0000

new_address_offset: int = 1


class Instruction:
    pc: int
    opcode: int
    operand: Optional[UnionType[bytes, BitVecRef]]

    def __init__(self, opcode, **kwargs) -> None:
        self.opcode = opcode

        self.pc = kwargs.get("pc", -1)
        self.operand = kwargs.get("operand", None)

    def __str__(self) -> str:
        operand_str = ""
        if self.operand is not None:
            operand = self.operand
            if isinstance(operand, bytes):
                operand = con(int.from_bytes(operand, "big"), len(operand) * 8)

            expected_operand_length = instruction_length(self.opcode) - 1
            actual_operand_length = operand.size() // 8
            if expected_operand_length != actual_operand_length:
                operand_str = f" ERROR {operand} ({expected_operand_length - actual_operand_length} bytes missed)"
            else:
                operand_str = " " + str(operand)

        return f"{mnemonic(self.opcode)}{operand_str}"

    def __repr__(self) -> str:
        return f"Instruction({mnemonic(self.opcode)}, pc={self.pc}, operand={repr(self.operand)})"

    def __len__(self) -> int:
        return instruction_length(self.opcode)


class HalmosException(Exception):
    pass


class NotConcreteError(HalmosException):
    pass


def id_str(x: Any) -> str:
    return hexify(x).replace(" ", "")


def name_of(x: str) -> str:
    return re.sub(r"\s+", "_", x)


def padded_slice(lst: List, start: int, size: int, default=0) -> List:
    """
    Return a slice of lst, starting at start and with size elements. If the slice
    is out of bounds, pad with default.
    """

    end = start + size
    n = len(lst)
    return [lst[i] if i < n else default for i in range(start, end)]


def unbox_int(x: Any) -> Any:
    """Convert int-like objects to int"""
    if isinstance(x, bytes):
        return int.from_bytes(x, "big")

    if is_bv_value(x):
        return x.as_long()

    return x


def int_of(x: Any, err: str = "expected concrete value but got") -> int:
    res = unbox_int(x)

    if isinstance(res, int):
        return res

    raise NotConcreteError(f"{err}: {x}")


def iter_bytes(x: Any, _byte_length: int = -1):
    """Return an iterable over the bytes of x (concrete or symbolic)"""

    if isinstance(x, bytes):
        return x

    if isinstance(x, int):
        # the byte length must be passed explicitly for ints, or this will fail
        return x.to_bytes(_byte_length, "big")

    if is_bv_value(x):
        return bv_value_to_bytes(x)

    if is_bv(x):
        if x.size() % 8 != 0:
            raise ValueError(x)

        # size in bytes
        size = x.size() // 8
        return [
            simplify(Extract((size - 1 - i) * 8 + 7, (size - 1 - i) * 8, x))
            for i in range(size)
        ]

    raise ValueError(x)


def is_concrete(x: Any) -> bool:
    return isinstance(x, int) or isinstance(x, bytes) or is_bv_value(x)


def mnemonic(opcode) -> str:
    if is_concrete(opcode):
        opcode = int_of(opcode)
        return str_opcode.get(opcode, hex(opcode))
    else:
        return str(opcode)


def concat(args):
    if len(args) > 1:
        return Concat(args)
    else:
        return args[0]


def uint256(x: BitVecRef) -> BitVecRef:
    bitsize = x.size()
    if bitsize > 256:
        raise ValueError(x)
    if bitsize == 256:
        return x
    return simplify(ZeroExt(256 - bitsize, x))


def uint160(x: BitVecRef) -> BitVecRef:
    bitsize = x.size()
    if bitsize > 256:
        raise ValueError(x)
    if bitsize == 160:
        return x
    if bitsize > 160:
        return simplify(Extract(159, 0, x))
    else:
        return simplify(ZeroExt(160 - bitsize, x))


def con(n: int, size_bits=256) -> Word:
    return BitVecVal(n, BitVecSorts[size_bits])


def byte_length(x: Any) -> int:
    if is_bv(x):
        if x.size() % 8 != 0:
            raise ValueError(x)
        return x.size() >> 3

    if isinstance(x, bytes):
        return len(x)

    raise ValueError(x)


def instruction_length(opcode: Any) -> int:
    opcode = int_of(opcode)
    return (opcode - EVM.PUSH0 + 1) if EVM.PUSH1 <= opcode <= EVM.PUSH32 else 1


def wextend(mem: List[UnionType[int, BitVecRef]], loc: int, size: int) -> None:
    mem.extend([0] * (loc + size - len(mem)))


def wload(
    mem: List[UnionType[int, BitVecRef]], loc: int, size: int, prefer_concrete=False
) -> UnionType[bytes, Bytes]:
    wextend(mem, loc, size)

    memslice = mem[loc : loc + size]

    # runtime sanity check: mem should only contain ints or BitVecs (not bytes)
    all_concrete = True
    for i in memslice:
        if isinstance(i, int):
            if not i in range(0, 256):
                raise ValueError(i)
            continue

        if is_bv(i):
            if not is_bv_value(i):
                all_concrete = False
            continue

        raise ValueError(i)

    if prefer_concrete and all_concrete:
        # will raise an error if any i is not in range(0, 256)
        return bytes([int_of(i) for i in memslice])

    # wrap concrete bytes in BitVecs
    # this would truncate the upper bits if the value didn't fit in 8 bits
    # therefore we rely on the value range check above to raise an error
    wrapped = [BitVecVal(i, BitVecSort8) if not is_bv(i) else i for i in memslice]

    # BitVecSorts[size * 8]
    return simplify(concat(wrapped))


def wstore(
    mem: List[UnionType[int, BitVecRef]], loc: int, size: int, val: Bytes
) -> None:
    if not eq(val.sort(), BitVecSorts[size * 8]):
        raise ValueError(val)
    wextend(mem, loc, size)
    for i in range(size):
        mem[loc + i] = simplify(
            Extract((size - 1 - i) * 8 + 7, (size - 1 - i) * 8, val)
        )


def wstore_partial(
    mem: List[UnionType[int, BitVecRef]],
    loc: int,
    offset: int,
    size: int,
    data: UnionType[bytes, Bytes],
    datasize: int,
) -> None:
    if size <= 0:
        return

    if not datasize >= offset + size:
        raise OutOfBoundsRead(datasize, offset, size)

    if is_bv(data):
        sub_data = Extract(
            (datasize - 1 - offset) * 8 + 7, (datasize - offset - size) * 8, data
        )
        wstore(mem, loc, size, sub_data)
    elif isinstance(data, bytes):
        sub_data = data[offset : offset + size]
        mem[loc : loc + size] = sub_data
    else:
        raise ValueError(data)


def wstore_bytes(
    mem: List[UnionType[int, BitVecRef]], loc: int, size: int, arr: List[Byte]
) -> None:
    if not size == len(arr):
        raise ValueError(size, arr)
    wextend(mem, loc, size)
    for i in range(size):
        if not eq(arr[i].sort(), BitVecSort8):
            raise ValueError(arr)
        mem[loc + i] = arr[i]


def extract_bytes(data: BitVecRef, byte_offset: int, size_bytes: int) -> BitVecRef:
    """Extract bytes from calldata. Zero-pad if out of bounds."""
    n = data.size()
    if n % 8 != 0:
        raise ValueError(n)

    # will extract hi - lo + 1 bits
    hi = n - 1 - byte_offset * 8
    lo = n - byte_offset * 8 - size_bytes * 8
    lo = 0 if lo < 0 else lo

    val = simplify(Extract(hi, lo, data))

    zero_padding = size_bytes * 8 - val.size()
    if zero_padding < 0:
        raise ValueError(val)
    if zero_padding > 0:
        val = simplify(Concat(val, con(0, zero_padding)))

    return val


def extract_funsig(calldata: BitVecRef):
    """Extracts the function signature (first 4 bytes) from calldata"""
    return extract_bytes(calldata, 0, 4)


def extract_string_argument(calldata: BitVecRef, arg_idx: int):
    """Extracts idx-th argument of string from calldata"""
    string_offset = int_of(
        extract_bytes(calldata, 4 + arg_idx * 32, 32),
        "symbolic offset for string argument",
    )
    string_length = int_of(
        extract_bytes(calldata, 4 + string_offset, 32),
        "symbolic size for string argument",
    )
    if string_length == 0:
        return ""
    string_value = int_of(
        extract_bytes(calldata, 4 + string_offset + 32, string_length),
        "symbolic string argument",
    )
    string_bytes = string_value.to_bytes(string_length, "big")
    return string_bytes.decode("utf-8")


def extract_string_array_argument(calldata: BitVecRef, arg_idx: int):
    """Extracts idx-th argument of string array from calldata"""

    array_slot = int_of(extract_bytes(calldata, 4 + 32 * arg_idx, 32))
    num_strings = int_of(extract_bytes(calldata, 4 + array_slot, 32))

    string_array = []

    for i in range(num_strings):
        string_offset = int_of(
            extract_bytes(calldata, 4 + array_slot + 32 * (i + 1), 32)
        )
        string_length = int_of(
            extract_bytes(calldata, 4 + array_slot + 32 + string_offset, 32)
        )
        string_value = int_of(
            extract_bytes(
                calldata, 4 + array_slot + 32 + string_offset + 32, string_length
            )
        )
        string_bytes = string_value.to_bytes(string_length, "big")
        string_array.append(string_bytes.decode("utf-8"))

    return string_array


def stringified_bytes_to_bytes(string_bytes: str):
    """Converts a string of bytes to a bytes memory type"""

    string_bytes_len = (len(string_bytes) + 1) // 2
    string_bytes_len_enc = hex(string_bytes_len).replace("0x", "").rjust(64, "0")

    string_bytes_len_ceil = (string_bytes_len + 31) // 32 * 32

    ret_bytes = (
        "00" * 31
        + "20"
        + string_bytes_len_enc
        + string_bytes.ljust(string_bytes_len_ceil * 2, "0")
    )
    ret_len = len(ret_bytes) // 2
    ret_bytes = bytes.fromhex(ret_bytes)

    return BitVecVal(int.from_bytes(ret_bytes, "big"), ret_len * 8)


@dataclass(frozen=True)
class EventLog:
    """
    Data record produced during the execution of a transaction.
    """

    address: Address
    topics: List[Word]
    data: Optional[Bytes]


@dataclass(frozen=True)
class Message:
    target: Address
    caller: Address
    value: Word
    data: List[Byte]
    is_static: bool = False
    call_scheme: int = EVM.CALL
    gas: Optional[Word] = None

    def is_create(self) -> bool:
        return self.call_scheme == EVM.CREATE or self.call_scheme == EVM.CREATE2


@dataclass
class CallOutput:
    """
    Data record produced during the execution of a call.
    """

    data: Optional[Bytes] = None
    accounts_to_delete: Set[Address] = field(default_factory=set)
    error: Optional[UnionType[EvmException, HalmosException]] = None
    return_scheme: Optional[int] = None

    # TODO:
    #   - touched_accounts
    # not modeled:
    #   - gas_refund
    #   - gas_left


TraceElement = UnionType["CallContext", EventLog]


@dataclass
class CallContext:
    message: Message
    output: CallOutput = field(default_factory=CallOutput)
    depth: int = 1
    trace: List[TraceElement] = field(default_factory=list)

    def subcalls(self) -> Iterator["CallContext"]:
        return iter(t for t in self.trace if isinstance(t, CallContext))

    def last_subcall(self) -> Optional["CallContext"]:
        """
        Returns the last subcall or None if there are no subcalls.
        """

        for c in reversed(self.trace):
            if isinstance(c, CallContext):
                return c

        return None

    def logs(self) -> Iterator[EventLog]:
        return iter(t for t in self.trace if isinstance(t, EventLog))

    def is_stuck(self) -> bool:
        """
        When called after execution, this method returns True if the call is stuck,
        i.e. it encountered an internal error and has no output.

        This is meaningless during execution, because the call may not yet have an output
        """
        return self.output.data is None

    def get_stuck_reason(self) -> Optional[HalmosException]:
        """
        Returns the first internal error encountered during the execution of the call.
        """
        if isinstance(self.output.error, HalmosException):
            return self.output.error

        if self.output.data is not None:
            # if this context has output data (including empty bytes), it is not stuck
            return None

        if (last_subcall := self.last_subcall()) is not None:
            return last_subcall.get_stuck_reason()


class State:
    stack: List[Word]
    memory: List[Byte]

    def __init__(self) -> None:
        self.stack: List[Word] = []
        self.memory: List[Byte] = []

    def __deepcopy__(self, memo):  # -> State:
        st = State()
        st.stack = self.stack.copy()
        st.memory = self.memory.copy()
        return st

    def __str__(self) -> str:
        return "".join(
            [
                f"Stack: {str(list(reversed(self.stack)))}\n",
                # self.str_memory(),
            ]
        )

    def str_memory(self) -> str:
        idx: int = 0
        ret: str = "Memory:"
        size: int = len(self.memory)
        while idx < size:
            ret += f"\n- {hex(idx)}: {self.memory[idx : min(idx + 32, size)]}"
            idx += 32
        return ret + "\n"

    def push(self, v: Word) -> None:
        if not (eq(v.sort(), BitVecSort256) or is_bool(v)):
            raise ValueError(v)
        self.stack.append(simplify(v))

    def pop(self) -> Word:
        return self.stack.pop()

    def dup(self, n: int) -> None:
        self.push(self.stack[-n])

    def swap(self, n: int) -> None:
        self.stack[-(n + 1)], self.stack[-1] = self.stack[-1], self.stack[-(n + 1)]

    def mloc(self) -> int:
        loc: int = int_of(self.pop(), "symbolic memory offset")
        return loc

    def mstore(self, full: bool) -> None:
        loc: int = self.mloc()
        val: Word = self.pop()
        if is_bool(val):
            val = If(val, con(1), con(0))
        if full:
            wstore(self.memory, loc, 32, val)
        else:  # mstore8
            wstore_bytes(self.memory, loc, 1, [simplify(Extract(7, 0, val))])

    def mload(self) -> None:
        loc: int = self.mloc()
        self.push(wload(self.memory, loc, 32))

    def ret(self) -> Bytes:
        loc: int = self.mloc()
        size: int = int_of(self.pop(), "symbolic return data size")  # size in bytes
        return wload(self.memory, loc, size, prefer_concrete=True) if size else b""


class Block:
    basefee: BitVecRef
    chainid: BitVecRef
    coinbase: Address
    difficulty: BitVecRef  # prevrandao
    gaslimit: BitVecRef
    number: BitVecRef
    timestamp: BitVecRef

    def __init__(self, **kwargs) -> None:
        self.basefee = kwargs["basefee"]
        self.chainid = kwargs["chainid"]
        self.coinbase = kwargs["coinbase"]
        self.difficulty = kwargs["difficulty"]
        self.gaslimit = kwargs["gaslimit"]
        self.number = kwargs["number"]
        self.timestamp = kwargs["timestamp"]

        assert_address(self.coinbase)


class Contract:
    """Abstraction over contract bytecode. Can include concrete and symbolic elements."""

    # for completely concrete code: _rawcode is a bytes object
    # for completely or partially symbolic code: _rawcode is a single BitVec element
    #    (typically a Concat() of concrete and symbolic values)
    _rawcode: UnionType[bytes, BitVecRef]

    def __init__(self, rawcode: UnionType[bytes, BitVecRef, str]) -> None:
        if rawcode is None:
            raise HalmosException("invalid contract code: None")

        if is_bv_value(rawcode):
            if rawcode.size() % 8 != 0:
                raise ValueError(rawcode)
            rawcode = rawcode.as_long().to_bytes(rawcode.size() // 8, "big")

        if isinstance(rawcode, str):
            rawcode = bytes.fromhex(rawcode)

        self._rawcode = rawcode

    def __init_jumpdests(self):
        self.jumpdests = set()

        for insn in iter(self):
            if insn.opcode == EVM.JUMPDEST:
                self.jumpdests.add(insn.pc)

    def __iter__(self):
        return CodeIterator(self)

    def from_hexcode(hexcode: str):
        """Create a contract from a hexcode string, e.g. "aabbccdd" """
        if not isinstance(hexcode, str):
            raise ValueError(hexcode)

        if len(hexcode) % 2 != 0:
            raise ValueError(hexcode)

        if hexcode.startswith("0x"):
            hexcode = hexcode[2:]

        if "__" in hexcode:
            warn(LIBRARY_PLACEHOLDER, f"contract hexcode contains library placeholder")

        try:
            return Contract(bytes.fromhex(hexcode))
        except ValueError as e:
            raise ValueError(f"{e} (hexcode={hexcode})")

    def decode_instruction(self, pc: int) -> Instruction:
        opcode = int_of(self[pc])

        if EVM.PUSH1 <= opcode <= EVM.PUSH32:
            operand = self[pc + 1 : pc + opcode - EVM.PUSH0 + 1]
            return Instruction(opcode, pc=pc, operand=operand)

        return Instruction(opcode, pc=pc)

    def next_pc(self, pc):
        opcode = self[pc]
        return pc + instruction_length(opcode)

    def __getslice__(self, slice):
        step = 1 if slice.step is None else slice.step
        if step != 1:
            return ValueError(f"slice step must be 1 but got {slice}")

        # symbolic
        if is_bv(self._rawcode):
            extracted = extract_bytes(
                self._rawcode, slice.start, slice.stop - slice.start
            )

            # check if that part of the code is concrete
            if is_bv_value(extracted):
                return bv_value_to_bytes(extracted)

            else:
                return extracted

        # concrete
        size = slice.stop - slice.start
        data = padded_slice(self._rawcode, slice.start, size, default=0)
        return bytes(data)

    def __getitem__(self, key) -> UnionType[int, BitVecRef]:
        """Returns the byte at the given offset."""
        if isinstance(key, slice):
            return self.__getslice__(key)

        offset = int_of(key, "symbolic index into contract bytecode")

        # support for negative indexing, e.g. contract[-1]
        if offset < 0:
            return self[len(self) + offset]

        # in the EVM, this is defined as returning 0
        if offset >= len(self):
            return 0

        # symbolic
        if is_bv(self._rawcode):
            extracted = extract_bytes(self._rawcode, offset, 1)

            # return as concrete if possible
            return unbox_int(extracted)

        # concrete
        return self._rawcode[offset]

    def __len__(self) -> int:
        """Returns the length of the bytecode in bytes."""
        return byte_length(self._rawcode)

    def valid_jump_destinations(self) -> set:
        """Returns the set of valid jump destinations."""
        if not hasattr(self, "jumpdests"):
            self.__init_jumpdests()

        return self.jumpdests


class CodeIterator:
    def __init__(self, contract: Contract):
        self.contract = contract
        self.pc = 0
        self.is_symbolic = is_bv(contract._rawcode)

    def __iter__(self):
        return self

    def __next__(self) -> Instruction:
        """Returns a tuple of (pc, opcode)"""
        if self.pc >= len(self.contract):
            raise StopIteration

        insn = self.contract.decode_instruction(self.pc)
        self.pc += len(insn)

        return insn


class Exec:  # an execution path
    # network
    code: Dict[Address, Contract]
    storage: Dict[Address, Dict[int, Any]]  # address -> { storage slot -> value }
    balance: Any  # address -> balance

    # block
    block: Block

    # tx
    context: CallContext

    # vm state
    this: Address  # current account address
    pgm: Contract
    pc: int
    st: State  # stack and memory
    jumpis: Dict[str, Dict[bool, int]]  # for loop detection
    symbolic: bool  # symbolic or concrete storage
    prank: Prank
    addresses_to_delete: Set[Address]

    # path
    solver: Solver
    path: List[Any]  # path conditions
    alias: Dict[Address, Address]  # address aliases

    # internal bookkeeping
    cnts: Dict[str, Dict[int, int]]  # opcode -> frequency; counters
    sha3s: Dict[Word, int]  # sha3 hashes generated
    storages: Dict[Any, Any]  # storage updates
    balances: Dict[Any, Any]  # balance updates
    calls: List[Any]  # external calls

    def __init__(self, **kwargs) -> None:
        self.code = kwargs["code"]
        self.storage = kwargs["storage"]
        self.balance = kwargs["balance"]
        #
        self.block = kwargs["block"]
        self.context = kwargs["context"]
        #
        self.this = kwargs["this"]
        self.pgm = kwargs["pgm"]
        self.pc = kwargs["pc"]
        self.st = kwargs["st"]
        self.jumpis = kwargs["jumpis"]
        self.symbolic = kwargs["symbolic"]
        self.prank = kwargs["prank"]
        self.addresses_to_delete = kwargs.get("addresses_to_delete") or set()
        #
        self.solver = kwargs["solver"]
        self.path = kwargs["path"]
        self.alias = kwargs["alias"]
        #
        self.cnts = kwargs["cnts"]
        self.sha3s = kwargs["sha3s"]
        self.storages = kwargs["storages"]
        self.balances = kwargs["balances"]
        self.calls = kwargs["calls"]

        assert_address(self.context.message.target)
        assert_address(self.context.message.caller)
        assert_address(self.this)

    def context_str(self) -> str:
        opcode = self.current_opcode()
        return f"addr={hexify(self.this)} pc={self.pc} insn={mnemonic(opcode)}"

    def halt(
        self,
        data: Bytes = EMPTY_BYTES,
        error: Optional[EvmException] = None,
    ) -> None:
        output = self.context.output
        if output.data is not None:
            raise HalmosException("output already set")

        output.data = data
        output.error = error
        output.return_scheme = self.current_opcode()

    def emit_log(self, log: EventLog):
        self.context.trace.append(log)

    def calldata(self) -> List[Byte]:
        message = self.message()
        return [] if message.is_create() else message.data

    def caller(self):
        return self.message().caller

    def callvalue(self):
        return self.message().value

    def message(self):
        return self.context.message

    def current_opcode(self) -> UnionType[int, BitVecRef]:
        return unbox_int(self.pgm[self.pc])

    def current_instruction(self) -> Instruction:
        return self.pgm.decode_instruction(self.pc)

    def str_cnts(self) -> str:
        return "".join(
            [
                f"{x[0]}: {x[1]}\n"
                for x in sorted(self.cnts["opcode"].items(), key=lambda x: x[0])
            ]
        )

    def str_solver(self) -> str:
        return "\n".join([str(cond) for cond in self.solver.assertions()])

    def str_path(self) -> str:
        return "".join(
            map(
                lambda x: "- " + str(x) + "\n",
                filter(lambda x: str(x) != "True", self.path),
            )
        )

    def __str__(self) -> str:
        output = self.context.output.data
        return hexify(
            "".join(
                [
                    f"PC: {self.this} {self.pc} {mnemonic(self.current_opcode())}\n",
                    str(self.st),
                    f"Balance: {self.balance}\n",
                    f"Storage:\n",
                    "".join(
                        map(
                            lambda x: f"- {x}: {self.storage[x]}\n",
                            self.storage,
                        )
                    ),
                    f"Path:\n{self.str_path()}",
                    f"Aliases:\n",
                    "".join([f"- {k}: {v}\n" for k, v in self.alias.items()]),
                    f"Output: {output.hex() if isinstance(output, bytes) else output}\n",
                    f"Balance updates:\n",
                    "".join(
                        map(
                            lambda x: f"- {x}\n",
                            sorted(self.balances.items(), key=lambda x: str(x[0])),
                        )
                    ),
                    f"Storage updates:\n",
                    "".join(
                        map(
                            lambda x: f"- {x}\n",
                            sorted(self.storages.items(), key=lambda x: str(x[0])),
                        )
                    ),
                    f"SHA3 hashes:\n",
                    "".join(map(lambda x: f"- {self.sha3s[x]}: {x}\n", self.sha3s)),
                    f"External calls:\n",
                    "".join(map(lambda x: f"- {x}\n", self.calls)),
                ]
            )
        )

    def next_pc(self) -> None:
        self.pc = self.pgm.next_pc(self.pc)

    def check(self, cond: Any) -> Any:
        self.solver.push()
        self.solver.add(simplify(cond))
        result = self.solver.check()
        self.solver.pop()
        return result

    def select(self, array: Any, key: Word, arrays: Dict) -> Word:
        if array in arrays:
            store = arrays[array]
            if store.decl().name() == "store" and store.num_args() == 3:
                base = store.arg(0)
                key0 = store.arg(1)
                val0 = store.arg(2)
                if eq(key, key0):  # structural equality
                    return val0
                if self.check(key == key0) == unsat:  # key != key0
                    return self.select(base, key, arrays)
                if self.check(key != key0) == unsat:  # key == key0
                    return val0
        # empty array
        elif not self.symbolic and re.search(r"^storage_.+_00$", str(array)):
            # note: simplifying empty array access might have a negative impact on solver performance
            return con(0)
        return Select(array, key)

    def balance_of(self, addr: Word) -> Word:
        assert_address(addr)
        value = self.select(self.balance, addr, self.balances)
        # practical assumption on the max balance per account
        self.solver.add(ULT(value, con(2**96)))
        return value

    def balance_update(self, addr: Word, value: Word) -> None:
        assert_address(addr)
        assert_uint256(value)
        new_balance_var = Array(
            f"balance_{1+len(self.balances):>02}", BitVecSort160, BitVecSort256
        )
        new_balance = Store(self.balance, addr, value)
        self.solver.add(new_balance_var == new_balance)
        self.balance = new_balance_var
        self.balances[new_balance_var] = new_balance

    def sha3(self) -> None:
        loc: int = self.st.mloc()
        size: int = int_of(self.st.pop(), "symbolic SHA3 data size")
        self.st.push(self.sha3_data(wload(self.st.memory, loc, size), size))

    def sha3_data(self, data: Bytes, size: int) -> Word:
        f_sha3 = Function("sha3_" + str(size * 8), BitVecSorts[size * 8], BitVecSort256)
        sha3_expr = f_sha3(data)

        # assume hash values are sufficiently smaller than the uint max
        self.solver.add(ULE(sha3_expr, con(2**256 - 2**64)))

        # assume no hash collision
        self.assume_sha3_distinct(sha3_expr)

        # handle create2 hash
        if size == 85 and eq(extract_bytes(data, 0, 1), con(0xFF, 8)):
            return con(create2_magic_address + self.sha3s[sha3_expr])
        else:
            return sha3_expr

    def assume_sha3_distinct(self, sha3_expr) -> None:
        # skip if already exist
        if sha3_expr in self.sha3s:
            return

        # we expect sha3_expr to be `sha3_<input-bitsize>(input_expr)`
        sha3_decl_name = sha3_expr.decl().name()

        for prev_sha3_expr in self.sha3s:
            if prev_sha3_expr.decl().name() == sha3_decl_name:
                # inputs have the same size: assume different inputs
                # lead to different outputs
                self.solver.add(
                    Implies(
                        sha3_expr.arg(0) != prev_sha3_expr.arg(0),
                        sha3_expr != prev_sha3_expr,
                    )
                )
            else:
                # inputs have different sizes: assume the outputs are different
                self.solver.add(sha3_expr != prev_sha3_expr)

        self.solver.add(sha3_expr != con(0))
        self.sha3s[sha3_expr] = len(self.sha3s)

    def new_gas_id(self) -> int:
        self.cnts["fresh"]["gas"] += 1
        return self.cnts["fresh"]["gas"]

    def new_address(self) -> Address:
        self.cnts["fresh"]["address"] += 1
        return con_addr(
            magic_address + new_address_offset + self.cnts["fresh"]["address"]
        )

    def new_symbol_id(self) -> int:
        self.cnts["fresh"]["symbol"] += 1
        return self.cnts["fresh"]["symbol"]

    def returndata(self) -> Optional[Bytes]:
        """
        Return data from the last executed sub-context or the empty bytes sequence
        """

        last_subcall = self.context.last_subcall()

        if not last_subcall:
            return EMPTY_BYTES

        output = last_subcall.output
        if last_subcall.message.is_create() and not output.error:
            return EMPTY_BYTES

        return output.data

    def returndatasize(self) -> int:
        returndata = self.returndata()
        return byte_length(returndata) if returndata is not None else 0

    def is_jumpdest(self, x: Word) -> bool:
        if not is_concrete(x):
            return False

        pc: int = int_of(x)
        if pc < 0:
            raise ValueError(pc)

        opcode = unbox_int(self.pgm[pc])
        return opcode == EVM.JUMPDEST

    def jumpi_id(self) -> str:
        return f"{self.pc}:" + ",".join(
            map(lambda x: str(x) if self.is_jumpdest(x) else "", self.st.stack)
        )

    # deploy libraries and resolve library placeholders in hexcode
    def resolve_libs(self, creation_hexcode, deployed_hexcode, lib_references) -> str:
        if lib_references:
            for lib in lib_references:
                address = self.new_address()

                self.code[address] = Contract.from_hexcode(
                    lib_references[lib]["hexcode"]
                )

                placeholder = lib_references[lib]["placeholder"]
                hex_address = hex(address.as_long())[2:].zfill(40)

                creation_hexcode = creation_hexcode.replace(placeholder, hex_address)
                deployed_hexcode = deployed_hexcode.replace(placeholder, hex_address)

        return (creation_hexcode, deployed_hexcode)


class Storage:
    @classmethod
    def normalize(cls, expr: Any) -> Any:
        # Concat(Extract(255, 8, bvadd(x, y)), bvadd(Extract(7, 0, x), Extract(7, 0, y))) => x + y
        if expr.decl().name() == "concat" and expr.num_args() == 2:
            arg0 = expr.arg(0)  # Extract(255, 8, bvadd(x, y))
            arg1 = expr.arg(1)  # bvadd(Extract(7, 0, x), Extract(7, 0, y))
            if (
                arg0.decl().name() == "extract"
                and arg0.num_args() == 1
                and arg0.params() == [255, 8]
            ):
                arg00 = arg0.arg(0)  # bvadd(x, y)
                if arg00.decl().name() == "bvadd":
                    x = arg00.arg(0)
                    y = arg00.arg(1)
                    if arg1.decl().name() == "bvadd" and arg1.num_args() == 2:
                        if eq(arg1.arg(0), simplify(Extract(7, 0, x))) and eq(
                            arg1.arg(1), simplify(Extract(7, 0, y))
                        ):
                            return x + y
        return expr


class SolidityStorage(Storage):
    @classmethod
    def empty(cls, addr: BitVecRef, slot: int, len_keys: int) -> ArrayRef:
        return Array(
            f"storage_{id_str(addr)}_{slot}_{len_keys}_00",
            BitVecSorts[len_keys * 256],
            BitVecSort256,
        )

    @classmethod
    def init(cls, ex: Exec, addr: Any, slot: int, keys) -> None:
        assert_address(addr)
        if slot not in ex.storage[addr]:
            ex.storage[addr][slot] = {}
        if len(keys) not in ex.storage[addr][slot]:
            if len(keys) == 0:
                if ex.symbolic:
                    label = f"storage_{id_str(addr)}_{slot}_{len(keys)}_00"
                    ex.storage[addr][slot][len(keys)] = BitVec(label, BitVecSort256)
                else:
                    ex.storage[addr][slot][len(keys)] = con(0)
            else:
                # do not use z3 const array `K(BitVecSort(len(keys)*256), con(0))` when not ex.symbolic
                # instead use normal smt array, and generate emptyness axiom; see load()
                ex.storage[addr][slot][len(keys)] = cls.empty(addr, slot, len(keys))

    @classmethod
    def load(cls, ex: Exec, addr: Any, loc: Word) -> Word:
        offsets = cls.decode(loc)
        if not len(offsets) > 0:
            raise ValueError(offsets)
        slot, keys = int_of(offsets[0], "symbolic storage base slot"), offsets[1:]
        cls.init(ex, addr, slot, keys)
        if len(keys) == 0:
            return ex.storage[addr][slot][0]
        else:
            if not ex.symbolic:
                # generate emptyness axiom for each array index, instead of using quantified formula; see init()
                ex.solver.add(
                    Select(cls.empty(addr, slot, len(keys)), concat(keys)) == con(0)
                )
            return ex.select(
                ex.storage[addr][slot][len(keys)], concat(keys), ex.storages
            )

    @classmethod
    def store(cls, ex: Exec, addr: Any, loc: Any, val: Any) -> None:
        offsets = cls.decode(loc)
        if not len(offsets) > 0:
            raise ValueError(offsets)
        slot, keys = int_of(offsets[0], "symbolic storage base slot"), offsets[1:]
        cls.init(ex, addr, slot, keys)
        if len(keys) == 0:
            ex.storage[addr][slot][0] = val
        else:
            new_storage_var = Array(
                f"storage_{id_str(addr)}_{slot}_{len(keys)}_{1+len(ex.storages):>02}",
                BitVecSorts[len(keys) * 256],
                BitVecSort256,
            )
            new_storage = Store(ex.storage[addr][slot][len(keys)], concat(keys), val)
            ex.solver.add(new_storage_var == new_storage)
            ex.storage[addr][slot][len(keys)] = new_storage_var
            ex.storages[new_storage_var] = new_storage

    @classmethod
    def decode(cls, loc: Any) -> Any:
        loc = cls.normalize(loc)
        if loc.decl().name() == "sha3_512":  # m[k] : hash(k.m)
            args = loc.arg(0)
            offset = simplify(Extract(511, 256, args))
            base = simplify(Extract(255, 0, args))
            return cls.decode(base) + (offset, con(0))
        elif loc.decl().name() == "sha3_256":  # a[i] : hash(a)+i
            base = loc.arg(0)
            return cls.decode(base) + (con(0),)
        elif loc.decl().name() == "bvadd":
            #   # when len(args) == 2
            #   arg0 = cls.decode(loc.arg(0))
            #   arg1 = cls.decode(loc.arg(1))
            #   if len(arg0) == 1 and len(arg1) > 1: # i + hash(x)
            #       return arg1[0:-1] + (arg1[-1] + arg0[0],)
            #   elif len(arg0) > 1 and len(arg1) == 1: # hash(x) + i
            #       return arg0[0:-1] + (arg0[-1] + arg1[0],)
            #   elif len(arg0) == 1 and len(arg1) == 1: # i + j
            #       return (arg0[0] + arg1[0],)
            #   else: # hash(x) + hash(y) # ambiguous
            #       raise ValueError(loc)
            # when len(args) >= 2
            args = loc.children()
            if len(args) < 2:
                raise ValueError(loc)
            args = sorted(map(cls.decode, args), key=lambda x: len(x), reverse=True)
            if len(args[1]) > 1:
                # only args[0]'s length >= 1, the others must be 1
                raise ValueError(loc)
            return args[0][0:-1] + (
                reduce(lambda r, x: r + x[0], args[1:], args[0][-1]),
            )
        elif is_bv_value(loc):
            (preimage, delta) = restore_precomputed_hashes(loc.as_long())
            if preimage:  # loc == hash(preimage) + delta
                return (con(preimage), con(delta))
            else:
                return (loc,)
        elif is_bv(loc):
            return (loc,)
        else:
            raise ValueError(loc)


class GenericStorage(Storage):
    @classmethod
    def empty(cls, addr: BitVecRef, loc: BitVecRef) -> ArrayRef:
        return Array(
            f"storage_{id_str(addr)}_{loc.size()}_00",
            BitVecSorts[loc.size()],
            BitVecSort256,
        )

    @classmethod
    def init(cls, ex: Exec, addr: Any, loc: BitVecRef) -> None:
        assert_address(addr)
        if loc.size() not in ex.storage[addr]:
            ex.storage[addr][loc.size()] = cls.empty(addr, loc)

    @classmethod
    def load(cls, ex: Exec, addr: Any, loc: Word) -> Word:
        loc = cls.decode(loc)
        cls.init(ex, addr, loc)
        if not ex.symbolic:
            # generate emptyness axiom for each array index, instead of using quantified formula; see init()
            ex.solver.add(Select(cls.empty(addr, loc), loc) == con(0))
        return ex.select(ex.storage[addr][loc.size()], loc, ex.storages)

    @classmethod
    def store(cls, ex: Exec, addr: Any, loc: Any, val: Any) -> None:
        loc = cls.decode(loc)
        cls.init(ex, addr, loc)
        new_storage_var = Array(
            f"storage_{id_str(addr)}_{loc.size()}_{1+len(ex.storages):>02}",
            BitVecSorts[loc.size()],
            BitVecSort256,
        )
        new_storage = Store(ex.storage[addr][loc.size()], loc, val)
        ex.solver.add(new_storage_var == new_storage)
        ex.storage[addr][loc.size()] = new_storage_var
        ex.storages[new_storage_var] = new_storage

    @classmethod
    def decode(cls, loc: Any) -> Any:
        loc = cls.normalize(loc)
        if loc.decl().name() == "sha3_512":  # hash(hi,lo), recursively
            args = loc.arg(0)
            hi = cls.decode(simplify(Extract(511, 256, args)))
            lo = cls.decode(simplify(Extract(255, 0, args)))
            return cls.simple_hash(Concat(hi, lo))
        elif loc.decl().name().startswith("sha3_"):
            return cls.simple_hash(cls.decode(loc.arg(0)))
        elif loc.decl().name() == "bvadd":
            args = loc.children()
            if len(args) < 2:
                raise ValueError(loc)
            return cls.add_all([cls.decode(arg) for arg in args])
        elif is_bv_value(loc):
            (preimage, delta) = restore_precomputed_hashes(loc.as_long())
            if preimage:  # loc == hash(preimage) + delta
                return cls.add_all([cls.simple_hash(con(preimage)), con(delta)])
            else:
                return loc
        elif is_bv(loc):
            return loc
        else:
            raise ValueError(loc)

    @classmethod
    def simple_hash(cls, x: BitVecRef) -> BitVecRef:
        # simple injective function for collision-free (though not secure) hash semantics, comprising:
        # - left-shift by 256 bits to ensure sufficient logical domain space
        # - an additional 1-bit for disambiguation (e.g., between map[key] vs array[i][j])
        return simplify(Concat(x, con(0, 257)))

    @classmethod
    def add_all(cls, args: List) -> BitVecRef:
        bitsize = max([x.size() for x in args])
        res = con(0, bitsize)
        for x in args:
            if x.size() < bitsize:
                x = simplify(ZeroExt(bitsize - x.size(), x))
            res += x
        return simplify(res)


SomeStorage = TypeVar("SomeStorage", bound=Storage)


#             x  == b   if sort(x) = bool
# int_to_bool(x) == b   if sort(x) = int
def test(x: Word, b: bool) -> Word:
    if is_bool(x):
        if b:
            return x
        else:
            return Not(x)
    elif is_bv(x):
        if b:
            return x != con(0)
        else:
            return x == con(0)
    else:
        raise ValueError(x)


def is_non_zero(x: Word) -> Word:
    return test(x, True)


def is_zero(x: Word) -> Word:
    return test(x, False)


def bitwise(op, x: Word, y: Word) -> Word:
    if is_bool(x) and is_bool(y):
        if op == EVM.AND:
            return And(x, y)
        elif op == EVM.OR:
            return Or(x, y)
        elif op == EVM.XOR:
            return Xor(x, y)
        else:
            raise ValueError(op, x, y)
    elif is_bv(x) and is_bv(y):
        if op == EVM.AND:
            return x & y
        elif op == EVM.OR:
            return x | y
        elif op == EVM.XOR:
            return x ^ y  # bvxor
        else:
            raise ValueError(op, x, y)
    elif is_bool(x) and is_bv(y):
        return bitwise(op, If(x, con(1), con(0)), y)
    elif is_bv(x) and is_bool(y):
        return bitwise(op, x, If(y, con(1), con(0)))
    else:
        raise ValueError(op, x, y)


def b2i(w: Word) -> Word:
    if is_true(w):
        return con(1)
    if is_false(w):
        return con(0)
    if is_bool(w):
        return If(w, con(1), con(0))
    else:
        return w


def is_power_of_two(x: int) -> bool:
    if x > 0:
        return not (x & (x - 1))
    else:
        return False


class HalmosLogs:
    bounded_loops: List[str]
    unknown_calls: Dict[str, Dict[str, Set[str]]]  # funsig -> to -> set(arg)

    def __init__(self) -> None:
        self.bounded_loops = []
        self.unknown_calls = defaultdict(lambda: defaultdict(set))

    def extend(self, logs: "HalmosLogs") -> None:
        self.bounded_loops.extend(logs.bounded_loops)
        for funsig in logs.unknown_calls:
            for to in logs.unknown_calls[funsig]:
                self.unknown_calls[funsig][to].update(logs.unknown_calls[funsig][to])

    def add_uninterpreted_unknown_call(self, funsig, to, arg):
        funsig, to, arg = hexify(funsig), hexify(to), hexify(arg)
        self.unknown_calls[funsig][to].add(arg)

    def print_unknown_calls(self):
        for funsig in self.unknown_calls:
            print(f"{funsig}:")
            for to in self.unknown_calls[funsig]:
                print(f"- {to}:")
                print(
                    "\n".join([f"  - {arg}" for arg in self.unknown_calls[funsig][to]])
                )


class SEVM:
    options: Dict
    storage_model: Type[SomeStorage]

    def __init__(self, options: Dict) -> None:
        self.options = options

        is_generic = self.options["storage_layout"] == "generic"
        self.storage_model = GenericStorage if is_generic else SolidityStorage

    def div_xy_y(self, w1: Word, w2: Word) -> Word:
        # return the number of bits required to represent the given value. default = 256
        def bitsize(w: Word) -> int:
            if (
                w.decl().name() == "concat"
                and is_bv_value(w.arg(0))
                and int(str(w.arg(0))) == 0
            ):
                return 256 - w.arg(0).size()
            return 256

        if w1.decl().name() == "bvmul" and w1.num_args() == 2:
            x = w1.arg(0)
            y = w1.arg(1)
            if eq(w2, x) or eq(w2, y):  # xy/x or xy/y
                size_x = bitsize(x)
                size_y = bitsize(y)
                if size_x + size_y <= 256:
                    if eq(w2, x):  # xy/x == y
                        return y
                    else:  # xy/y == x
                        return x
        return None

    def mk_div(self, ex: Exec, x: Any, y: Any) -> Any:
        term = f_div(x, y)
        ex.solver.add(ULE(term, x))  # (x / y) <= x
        return term

    def mk_mod(self, ex: Exec, x: Any, y: Any) -> Any:
        term = f_mod[x.size()](x, y)
        ex.solver.add(ULE(term, y))  # (x % y) <= y
        # ex.solver.add(Or(y == con(0), ULT(term, y))) # (x % y) < y if y != 0
        return term

    def arith(self, ex: Exec, op: int, w1: Word, w2: Word) -> Word:
        w1 = b2i(w1)
        w2 = b2i(w2)

        if op == EVM.ADD:
            return w1 + w2

        if op == EVM.SUB:
            return w1 - w2

        if op == EVM.MUL:
            return w1 * w2

        if op == EVM.DIV:
            div_for_overflow_check = self.div_xy_y(w1, w2)
            if div_for_overflow_check is not None:  # xy/x or xy/y
                return div_for_overflow_check

            if is_bv_value(w1) and is_bv_value(w2):
                return UDiv(w1, w2)  # unsigned div (bvudiv)

            if is_bv_value(w2):
                # concrete denominator case
                i2: int = w2.as_long()
                if i2 == 0:
                    return w2

                if i2 == 1:
                    return w1

                if is_power_of_two(i2):
                    return LShR(w1, int(math.log(i2, 2)))

            return self.mk_div(ex, w1, w2)

        if op == EVM.MOD:
            if is_bv_value(w1) and is_bv_value(w2):
                return URem(w1, w2)  # bvurem

            if is_bv_value(w2):
                i2: int = int(str(w2))
                if i2 == 0 or i2 == 1:
                    return con(0, w2.size())

                if is_power_of_two(i2):
                    bitsize = int(math.log(i2, 2))
                    return ZeroExt(w2.size() - bitsize, Extract(bitsize - 1, 0, w1))

            return self.mk_mod(ex, w1, w2)

        if op == EVM.SDIV:
            if is_bv_value(w1) and is_bv_value(w2):
                return w1 / w2  # bvsdiv

            if is_bv_value(w2):
                # concrete denominator case
                i2: int = w2.as_long()
                if i2 == 0:
                    return w2  # div by 0 is 0

                if i2 == 1:
                    return w1  # div by 1 is identity

            # fall back to uninterpreted function :(
            return f_sdiv(w1, w2)

        if op == EVM.SMOD:
            if is_bv_value(w1) and is_bv_value(w2):
                return SRem(w1, w2)  # bvsrem  # vs: w1 % w2 (bvsmod w1 w2)

            # TODO: if is_bv_value(w2):

            return f_smod(w1, w2)

        if op == EVM.EXP:
            if is_bv_value(w1) and is_bv_value(w2):
                i1: int = int(str(w1))  # must be concrete
                i2: int = int(str(w2))  # must be concrete
                return con(i1**i2)

            if is_bv_value(w2):
                i2: int = int(str(w2))
                if i2 == 0:
                    return con(1)

                if i2 == 1:
                    return w1

                if i2 <= self.options.get("expByConst"):
                    exp = w1
                    for _ in range(i2 - 1):
                        exp = exp * w1
                    return exp

            return f_exp(w1, w2)

        raise ValueError(op)

    def arith2(self, ex: Exec, op: int, w1: Word, w2: Word, w3: Word) -> Word:
        w1 = b2i(w1)
        w2 = b2i(w2)
        w3 = b2i(w3)
        if op == EVM.ADDMOD:
            # to avoid add overflow; and to be a multiple of 8-bit
            r1 = self.arith(
                ex, EVM.ADD, simplify(ZeroExt(8, w1)), simplify(ZeroExt(8, w2))
            )
            r2 = self.arith(ex, EVM.MOD, simplify(r1), simplify(ZeroExt(8, w3)))
            if r1.size() != 264:
                raise ValueError(r1)
            if r2.size() != 264:
                raise ValueError(r2)
            return Extract(255, 0, r2)
        elif op == EVM.MULMOD:
            # to avoid mul overflow
            r1 = self.arith(
                ex, EVM.MUL, simplify(ZeroExt(256, w1)), simplify(ZeroExt(256, w2))
            )
            r2 = self.arith(ex, EVM.MOD, simplify(r1), simplify(ZeroExt(256, w3)))
            if r1.size() != 512:
                raise ValueError(r1)
            if r2.size() != 512:
                raise ValueError(r2)
            return Extract(255, 0, r2)
        else:
            raise ValueError(op)

    def sload(self, ex: Exec, addr: Any, loc: Word) -> Word:
        return self.storage_model.load(ex, addr, loc)

    def sstore(self, ex: Exec, addr: Any, loc: Any, val: Any) -> None:
        if ex.message().is_static:
            raise WriteInStaticContext(ex.context_str())

        if is_bool(val):
            val = If(val, con(1), con(0))

        self.storage_model.store(ex, addr, loc, val)

    def resolve_address_alias(self, ex: Exec, target: Address) -> Address:
        if target in ex.code:
            return target

        if target not in ex.alias:
            for addr in ex.code:
                if ex.check(target != addr) == unsat:  # target == addr
                    if self.options.get("debug"):
                        print(
                            f"[DEBUG] Address alias: {hexify(addr)} for {hexify(target)}"
                        )
                    ex.alias[target] = addr
                    ex.solver.add(target == addr)
                    break

        return ex.alias.get(target)

    def transfer_value(
        self,
        ex: Exec,
        caller: Address,
        to: Address,
        value: Word,
        condition: Word = None,
    ) -> None:
        # no-op if value is zero
        if is_bv_value(value) and value.as_long() == 0:
            return

        # assume balance is enough; otherwise ignore this path
        # note: evm requires enough balance even for self-transfer
        balance_cond = simplify(UGE(ex.balance_of(caller), value))
        ex.solver.add(balance_cond)
        ex.path.append(str(balance_cond))

        # conditional transfer
        if condition is not None:
            value = If(condition, value, con(0))

        ex.balance_update(caller, self.arith(ex, EVM.SUB, ex.balance_of(caller), value))
        ex.balance_update(to, self.arith(ex, EVM.ADD, ex.balance_of(to), value))

    def call(
        self,
        ex: Exec,
        op: int,
        stack: List[Tuple[Exec, int]],
        step_id: int,
        out: List[Exec],
        logs: HalmosLogs,
    ) -> None:
        gas = ex.st.pop()
        to = uint160(ex.st.pop())
        fund = con(0) if op in [EVM.STATICCALL, EVM.DELEGATECALL] else ex.st.pop()

        arg_loc: int = ex.st.mloc()
        arg_size: int = int_of(ex.st.pop(), "symbolic CALL input data size")

        ret_loc: int = ex.st.mloc()
        ret_size: int = int_of(ex.st.pop(), "symbolic CALL return data size")

        if not arg_size >= 0:
            raise ValueError(arg_size)
        if not ret_size >= 0:
            raise ValueError(ret_size)

        arg = wload(ex.st.memory, arg_loc, arg_size) if arg_size > 0 else None
        caller = ex.prank.lookup(ex.this, to)

        def send_callvalue(condition=None) -> None:
            # no balance update for CALLCODE which transfers to itself
            if op == EVM.CALL:
                # TODO: revert if context is static
                self.transfer_value(ex, caller, to, fund, condition)

        def call_known(to: Address) -> None:
            # backup current state
            orig_code = ex.code.copy()
            orig_storage = deepcopy(ex.storage)
            orig_balance = ex.balance

            # transfer msg.value
            send_callvalue()

            # prepare calldata
            calldata = [None] * arg_size
            wextend(ex.st.memory, arg_loc, arg_size)
            wstore_bytes(
                calldata, 0, arg_size, ex.st.memory[arg_loc : arg_loc + arg_size]
            )

            message = Message(
                target=to if op in [EVM.CALL, EVM.STATICCALL] else ex.this,
                caller=caller if op != EVM.DELEGATECALL else ex.caller(),
                value=fund if op != EVM.DELEGATECALL else ex.callvalue(),
                data=calldata,
                is_static=(ex.context.message.is_static or op == EVM.STATICCALL),
                call_scheme=op,
            )

            # TODO: check max call depth

            # execute external calls
            (new_exs, new_steps, new_logs) = self.run(
                Exec(
                    code=ex.code,
                    storage=ex.storage,
                    balance=ex.balance,
                    #
                    block=ex.block,
                    #
                    context=CallContext(message=message, depth=ex.context.depth + 1),
                    this=message.target,
                    #
                    pgm=ex.code[to],
                    pc=0,
                    st=State(),
                    jumpis={},
                    symbolic=ex.symbolic,
                    prank=Prank(),
                    #
                    solver=ex.solver,
                    path=ex.path,
                    alias=ex.alias,
                    #
                    cnts=ex.cnts,
                    sha3s=ex.sha3s,
                    storages=ex.storages,
                    balances=ex.balances,
                    calls=ex.calls,
                )
            )

            logs.extend(new_logs)

            # process result
            for new_ex in new_exs:
                # continue execution in the context of the parent
                # pessimistic copy because the subcall results may diverge
                subcall = new_ex.context

                # restore context
                new_ex.context = deepcopy(ex.context)
                new_ex.context.trace.append(subcall)
                new_ex.this = ex.this

                if subcall.is_stuck():
                    # internal errors abort the current path,
                    # so we don't need to add it to the worklist
                    out.append(new_ex)
                    continue

                # restore vm state
                new_ex.pgm = ex.pgm
                new_ex.pc = ex.pc
                new_ex.st = deepcopy(ex.st)
                new_ex.jumpis = deepcopy(ex.jumpis)
                new_ex.symbolic = ex.symbolic
                new_ex.prank = deepcopy(ex.prank)

                # set return data (in memory)
                actual_ret_size = new_ex.returndatasize()
                wstore_partial(
                    new_ex.st.memory,
                    ret_loc,
                    0,
                    min(ret_size, actual_ret_size),
                    subcall.output.data,
                    actual_ret_size,
                )

                # set status code on the stack
                subcall_success = subcall.output.error is None
                new_ex.st.push(con(1) if subcall_success else con(0))

                if not subcall_success:
                    # revert network states
                    new_ex.code = orig_code
                    new_ex.storage = orig_storage
                    new_ex.balance = orig_balance

                # add to worklist even if it reverted during the external call
                new_ex.next_pc()
                stack.append((new_ex, step_id))

        def call_unknown() -> None:
            call_id = len(ex.calls)

            # push exit code
            if arg_size > 0:
                f_call = Function(
                    "call_" + str(arg_size * 8),
                    BitVecSort256,  # cnt
                    BitVecSort256,  # gas
                    BitVecSort160,  # to
                    BitVecSort256,  # value
                    BitVecSorts[arg_size * 8],  # args
                    BitVecSort256,
                )
                exit_code = f_call(con(call_id), gas, to, fund, arg)
            else:
                f_call = Function(
                    "call_" + str(arg_size * 8),
                    BitVecSort256,  # cnt
                    BitVecSort256,  # gas
                    BitVecSort160,  # to
                    BitVecSort256,  # value
                    BitVecSort256,
                )
                exit_code = f_call(con(call_id), gas, to, fund)
            exit_code_var = BitVec(f"call_exit_code_{call_id:>02}", BitVecSort256)
            ex.solver.add(exit_code_var == exit_code)
            ex.st.push(exit_code_var)

            # transfer msg.value
            send_callvalue(exit_code_var != con(0))

            if ret_size > 0:
                # actual return data will be capped or zero-padded by ret_size
                # FIX: this doesn't capture the case of returndatasize != ret_size
                actual_ret_size = ret_size
            else:
                actual_ret_size = self.options["unknown_calls_return_size"]

            if actual_ret_size > 0:
                f_ret = Function(
                    "ret_" + str(actual_ret_size * 8),
                    BitVecSort256,
                    BitVecSorts[actual_ret_size * 8],
                )
                ret = f_ret(exit_code_var)
            else:
                ret = None

            # TODO: cover other precompiled

            # ecrecover
            if eq(to, con_addr(1)):
                ex.solver.add(exit_code_var != con(0))

            # identity
            if eq(to, con_addr(4)):
                ex.solver.add(exit_code_var != con(0))
                ret = arg

            # TODO: factor out cheatcode semantics
            # halmos cheat code
            if eq(to, halmos_cheat_code.address):
                ex.solver.add(exit_code_var != con(0))

                funsig: int = int_of(
                    extract_funsig(arg), "symbolic halmos cheatcode function selector"
                )

                if self.options.get("debug"):
                    print(f"Executing halmos cheat code: {hex(funsig)}")

                # createUint(uint256,string) returns (uint256)
                if funsig == halmos_cheat_code.create_uint:
                    bit_size = int_of(
                        extract_bytes(arg, 4, 32),
                        "symbolic bit size for halmos.createUint()",
                    )
                    name = name_of(extract_string_argument(arg, 1))
                    if bit_size <= 256:
                        label = f"halmos_{name}_uint{bit_size}_{ex.new_symbol_id():>02}"
                        ret = uint256(BitVec(label, BitVecSorts[bit_size]))
                    else:
                        raise HalmosException(f"bitsize larger than 256: {bit_size}")

                # createBytes(uint256,string) returns (bytes)
                elif funsig == halmos_cheat_code.create_bytes:
                    byte_size = int_of(
                        extract_bytes(arg, 4, 32),
                        "symbolic byte size for halmos.createBytes()",
                    )
                    name = name_of(extract_string_argument(arg, 1))
                    label = f"halmos_{name}_bytes_{ex.new_symbol_id():>02}"
                    symbolic_bytes = BitVec(label, BitVecSorts[byte_size * 8])
                    ret = Concat(con(32), con(byte_size), symbolic_bytes)

                # createUint256(string) returns (uint256)
                elif funsig == halmos_cheat_code.create_uint256:
                    name = name_of(extract_string_argument(arg, 0))
                    label = f"halmos_{name}_uint256_{ex.new_symbol_id():>02}"
                    ret = BitVec(label, BitVecSort256)

                # createBytes32(string) returns (bytes32)
                elif funsig == halmos_cheat_code.create_bytes32:
                    name = name_of(extract_string_argument(arg, 0))
                    label = f"halmos_{name}_bytes32_{ex.new_symbol_id():>02}"
                    ret = BitVec(label, BitVecSort256)

                # createAddress(string) returns (address)
                elif funsig == halmos_cheat_code.create_address:
                    name = name_of(extract_string_argument(arg, 0))
                    label = f"halmos_{name}_address_{ex.new_symbol_id():>02}"
                    ret = uint256(BitVec(label, BitVecSort160))

                # createBool(string) returns (bool)
                elif funsig == halmos_cheat_code.create_bool:
                    name = name_of(extract_string_argument(arg, 0))
                    label = f"halmos_{name}_bool_{ex.new_symbol_id():>02}"
                    ret = uint256(BitVec(label, BitVecSort1))

                else:
                    error_msg = f"Unknown halmos cheat code: function selector = 0x{funsig:0>8x}, calldata = {hexify(arg)}"
                    raise HalmosException(error_msg)

            # vm cheat code
            if eq(to, hevm_cheat_code.address):
                ex.solver.add(exit_code_var != con(0))
                # vm.fail()
                # BitVecVal(hevm_cheat_code.fail_payload, 800)
                if arg == hevm_cheat_code.fail_payload:
                    raise FailCheatcode()

                # vm.assume(bool)
                elif (
                    eq(arg.sort(), BitVecSorts[(4 + 32) * 8])
                    and simplify(Extract(287, 256, arg)) == hevm_cheat_code.assume_sig
                ):
                    assume_cond = simplify(is_non_zero(Extract(255, 0, arg)))
                    ex.solver.add(assume_cond)
                    ex.path.append(str(assume_cond))

                # vm.getCode(string)
                elif (
                    simplify(Extract(arg_size * 8 - 1, arg_size * 8 - 32, arg))
                    == hevm_cheat_code.get_code_sig
                ):
                    calldata = bytes.fromhex(hex(arg.as_long())[2:])
                    path_len = int.from_bytes(calldata[36:68], "big")
                    path = calldata[68 : 68 + path_len].decode("utf-8")

                    if ":" in path:
                        [filename, contract_name] = path.split(":")
                        path = "out/" + filename + "/" + contract_name + ".json"

                    target = self.options["target"].rstrip("/")
                    path = target + "/" + path

                    with open(path) as f:
                        artifact = json.loads(f.read())

                    if artifact["bytecode"]["object"]:
                        bytecode = artifact["bytecode"]["object"].replace("0x", "")
                    else:
                        bytecode = artifact["bytecode"].replace("0x", "")

                    ret = stringified_bytes_to_bytes(bytecode)
                # vm.prank(address)
                elif (
                    eq(arg.sort(), BitVecSorts[(4 + 32) * 8])
                    and simplify(Extract(287, 256, arg)) == hevm_cheat_code.prank_sig
                ):
                    result = ex.prank.prank(uint160(Extract(255, 0, arg)))
                    if not result:
                        raise HalmosException("You have an active prank already.")

                # vm.startPrank(address)
                elif (
                    eq(arg.sort(), BitVecSorts[(4 + 32) * 8])
                    and simplify(Extract(287, 256, arg))
                    == hevm_cheat_code.start_prank_sig
                ):
                    result = ex.prank.startPrank(uint160(Extract(255, 0, arg)))
                    if not result:
                        raise HalmosException("You have an active prank already.")

                # vm.stopPrank()
                elif (
                    eq(arg.sort(), BitVecSorts[4 * 8])
                    and simplify(Extract(31, 0, arg)) == hevm_cheat_code.stop_prank_sig
                ):
                    ex.prank.stopPrank()
                # vm.deal(address,uint256)
                elif (
                    eq(arg.sort(), BitVecSorts[(4 + 32 * 2) * 8])
                    and simplify(Extract(543, 512, arg)) == hevm_cheat_code.deal_sig
                ):
                    who = uint160(Extract(511, 256, arg))
                    amount = simplify(Extract(255, 0, arg))
                    ex.balance_update(who, amount)
                # vm.store(address,bytes32,bytes32)
                elif (
                    eq(arg.sort(), BitVecSorts[(4 + 32 * 3) * 8])
                    and simplify(Extract(799, 768, arg)) == hevm_cheat_code.store_sig
                ):
                    store_account = uint160(Extract(767, 512, arg))
                    store_slot = simplify(Extract(511, 256, arg))
                    store_value = simplify(Extract(255, 0, arg))
                    store_account_addr = self.resolve_address_alias(ex, store_account)
                    if store_account_addr is not None:
                        self.sstore(ex, store_account_addr, store_slot, store_value)
                    else:
                        raise HalmosException(f"uninitialized account: {store_account}")

                # vm.load(address,bytes32)
                elif (
                    eq(arg.sort(), BitVecSorts[(4 + 32 * 2) * 8])
                    and simplify(Extract(543, 512, arg)) == hevm_cheat_code.load_sig
                ):
                    load_account = uint160(Extract(511, 256, arg))
                    load_slot = simplify(Extract(255, 0, arg))
                    load_account_addr = self.resolve_address_alias(ex, load_account)
                    if load_account_addr is not None:
                        ret = self.sload(ex, load_account_addr, load_slot)
                    else:
                        raise HalmosException(f"uninitialized account: {store_account}")

                # vm.fee(uint256)
                elif (
                    eq(arg.sort(), BitVecSorts[(4 + 32) * 8])
                    and simplify(Extract(287, 256, arg)) == hevm_cheat_code.fee_sig
                ):
                    ex.block.basefee = simplify(Extract(255, 0, arg))
                # vm.chainId(uint256)
                elif (
                    eq(arg.sort(), BitVecSorts[(4 + 32) * 8])
                    and simplify(Extract(287, 256, arg)) == hevm_cheat_code.chainid_sig
                ):
                    ex.block.chainid = simplify(Extract(255, 0, arg))
                # vm.coinbase(address)
                elif (
                    eq(arg.sort(), BitVecSorts[(4 + 32) * 8])
                    and simplify(Extract(287, 256, arg)) == hevm_cheat_code.coinbase_sig
                ):
                    ex.block.coinbase = uint160(Extract(255, 0, arg))
                # vm.difficulty(uint256)
                elif (
                    eq(arg.sort(), BitVecSorts[(4 + 32) * 8])
                    and simplify(Extract(287, 256, arg))
                    == hevm_cheat_code.difficulty_sig
                ):
                    ex.block.difficulty = simplify(Extract(255, 0, arg))
                # vm.roll(uint256)
                elif (
                    eq(arg.sort(), BitVecSorts[(4 + 32) * 8])
                    and simplify(Extract(287, 256, arg)) == hevm_cheat_code.roll_sig
                ):
                    ex.block.number = simplify(Extract(255, 0, arg))
                # vm.warp(uint256)
                elif (
                    eq(arg.sort(), BitVecSorts[(4 + 32) * 8])
                    and simplify(Extract(287, 256, arg)) == hevm_cheat_code.warp_sig
                ):
                    ex.block.timestamp = simplify(Extract(255, 0, arg))
                # vm.etch(address,bytes)
                elif extract_funsig(arg) == hevm_cheat_code.etch_sig:
                    who = extract_bytes(arg, 4 + 12, 20)

                    # who must be concrete
                    if not is_bv_value(who):
                        error_msg = f"vm.etch(address who, bytes code) must have concrete argument `who` but received {who}"
                        raise HalmosException(error_msg)

                    # code must be concrete
                    try:
                        code_offset = int_of(extract_bytes(arg, 4 + 32, 32))
                        code_length = int_of(extract_bytes(arg, 4 + code_offset, 32))
                        code_int = int_of(
                            extract_bytes(arg, 4 + code_offset + 32, code_length)
                        )
                        code_bytes = code_int.to_bytes(code_length, "big")

                        ex.code[who] = Contract(code_bytes)
                    except Exception as e:
                        error_msg = f"vm.etch(address who, bytes code) must have concrete argument `code` but received calldata {arg}"
                        raise HalmosException(error_msg) from e
                # ffi(string[]) returns (bytes)
                elif extract_funsig(arg) == hevm_cheat_code.ffi_sig:
                    if not self.options.get("ffi"):
                        error_msg = "ffi cheatcode is disabled. Run again with `--ffi` if you want to enable it"
                        raise HalmosException(error_msg)
                    cmd = extract_string_array_argument(arg, 0)
                    process = Popen(cmd, stdout=PIPE, stderr=PIPE)

                    (stdout, stderr) = process.communicate()

                    if stderr:
                        warn(
                            INTERNAL_ERROR,
                            f"An exception has occurred during the usage of the ffi cheatcode:\n{stderr.decode('utf-8')}",
                        )

                    out_bytes = stdout.decode("utf-8")

                    if not out_bytes.startswith("0x"):
                        out_bytes = out_bytes.strip().encode("utf-8").hex()
                    else:
                        out_bytes = out_bytes.strip().replace("0x", "")

                    ret = stringified_bytes_to_bytes(out_bytes)

                else:
                    # TODO: support other cheat codes
                    msg = f"Unsupported cheat code: calldata = {hexify(arg)}"
                    raise HalmosException(msg)

            # console
            if eq(to, console.address):
                ex.solver.add(exit_code_var != con(0))

                funsig: int = int_of(
                    extract_funsig(arg), "symbolic console function selector"
                )

                if funsig == console.log_uint256:
                    print(extract_bytes(arg, 4, 32))

                # elif funsig == console.log_string:

                else:
                    # TODO: support other console functions
                    print(
                        color_info(
                            f"Unsupported console function: selector = 0x{funsig:0>8x}, "
                            f"calldata = {hexify(arg)}"
                        )
                    )

            # store return value
            if ret_size > 0:
                wstore(ex.st.memory, ret_loc, ret_size, ret)

            ex.context.trace.append(
                CallContext(
                    message=Message(
                        target=to,
                        caller=caller,
                        value=fund,
                        data=ex.st.memory[arg_loc : arg_loc + arg_size],
                        call_scheme=op,
                    ),
                    output=CallOutput(
                        data=ret,
                        error=None,
                    ),
                    depth=ex.context.depth + 1,
                )
            )

            # TODO: check if still needed
            ex.calls.append((exit_code_var, exit_code, ex.context.output.data))

            ex.next_pc()
            stack.append((ex, step_id))

        # precompiles or cheatcodes
        if (
            # precompile
            eq(to, con_addr(1))
            or eq(to, con_addr(4))
            # cheatcode calls
            or eq(to, halmos_cheat_code.address)
            or eq(to, hevm_cheat_code.address)
            or eq(to, console.address)
        ):
            call_unknown()
            return

        # known call target
        to_addr = self.resolve_address_alias(ex, to)
        if to_addr is not None:
            call_known(to_addr)
            return

        # simple ether transfer to unknown call target
        if arg_size == 0:
            call_unknown()
            return

        # uninterpreted unknown calls
        funsig = extract_funsig(arg)
        if funsig in self.options["unknown_calls"]:
            logs.add_uninterpreted_unknown_call(funsig, to, arg)
            call_unknown()
            return

        raise HalmosException(
            f"Unknown contract call: to = {hexify(to)}; "
            f"calldata = {hexify(arg)}; callvalue = {hexify(fund)}"
        )

    def create(
        self,
        ex: Exec,
        op: int,
        stack: List[Tuple[Exec, int]],
        step_id: int,
        out: List[Exec],
        logs: HalmosLogs,
    ) -> None:
        if ex.message().is_static:
            raise WriteInStaticContext(ex.context_str())

        value: Word = ex.st.pop()
        loc: int = int_of(ex.st.pop(), "symbolic CREATE offset")
        size: int = int_of(ex.st.pop(), "symbolic CREATE size")

        if op == EVM.CREATE2:
            salt = ex.st.pop()

        # lookup prank
        caller = ex.prank.lookup(ex.this, con_addr(0))

        # contract creation code
        create_hexcode = wload(ex.st.memory, loc, size, prefer_concrete=True)
        create_code = Contract(create_hexcode)

        # new account address
        if op == EVM.CREATE:
            new_addr = ex.new_address()
        elif op == EVM.CREATE2:  # EVM.CREATE2
            if isinstance(create_hexcode, bytes):
                create_hexcode = con(
                    int.from_bytes(create_hexcode, "big"), len(create_hexcode) * 8
                )
            code_hash = ex.sha3_data(create_hexcode, create_hexcode.size() // 8)
            hash_data = simplify(Concat(con(0xFF, 8), caller, salt, code_hash))
            new_addr = uint160(ex.sha3_data(hash_data, 85))
        else:
            raise HalmosException(f"Unknown CREATE opcode: {op}")

        message = Message(
            target=new_addr,
            caller=caller,
            value=value,
            data=create_hexcode,
            is_static=False,
            call_scheme=op,
        )

        if new_addr in ex.code:
            # address conflicts don't revert, they push 0 on the stack and continue
            ex.st.push(con(0))
            ex.next_pc()

            # add a virtual subcontext to the trace for debugging purposes
            subcall = CallContext(message=message, depth=ex.context.depth + 1)
            subcall.output.data = b""
            subcall.output.error = AddressCollision()
            ex.context.trace.append(subcall)

            stack.append((ex, step_id))
            return

        for addr in ex.code:
            ex.solver.add(new_addr != addr)  # ensure new address is fresh

        # backup current state
        orig_code = ex.code.copy()
        orig_storage = deepcopy(ex.storage)
        orig_balance = ex.balance

        # setup new account
        ex.code[new_addr] = Contract(b"")  # existing code must be empty
        ex.storage[new_addr] = {}  # existing storage may not be empty and reset here

        # transfer value
        self.transfer_value(ex, caller, new_addr, value)

        # execute contract creation code
        (new_exs, new_steps, new_logs) = self.run(
            Exec(
                code=ex.code,
                storage=ex.storage,
                balance=ex.balance,
                #
                block=ex.block,
                #
                context=CallContext(message=message, depth=ex.context.depth + 1),
                this=new_addr,
                #
                pgm=create_code,
                pc=0,
                st=State(),
                jumpis={},
                symbolic=False,
                prank=Prank(),
                #
                solver=ex.solver,
                path=ex.path,
                alias=ex.alias,
                #
                cnts=ex.cnts,
                sha3s=ex.sha3s,
                storages=ex.storages,
                balances=ex.balances,
                calls=ex.calls,
            )
        )

        logs.extend(new_logs)

        # process result
        for new_ex in new_exs:
            subcall = new_ex.context

            # continue execution in the context of the parent
            # pessimistic copy because the subcall results may diverge
            new_ex.context = deepcopy(ex.context)
            new_ex.context.trace.append(subcall)

            new_ex.this = ex.this

            # restore vm state
            new_ex.pgm = ex.pgm
            new_ex.pc = ex.pc
            new_ex.st = deepcopy(ex.st)
            new_ex.jumpis = deepcopy(ex.jumpis)
            new_ex.symbolic = ex.symbolic
            new_ex.prank = deepcopy(ex.prank)

            if subcall.is_stuck():
                # internal errors abort the current path,
                out.append(new_ex)
                continue

            elif subcall.output.error is None:
                # new contract code, will revert if data is None
                new_ex.code[new_addr] = Contract(subcall.output.data)

                # push new address to stack
                new_ex.st.push(uint256(new_addr))

            else:
                # creation failed
                new_ex.st.push(con(0))

                # revert network states
                new_ex.code = orig_code
                new_ex.storage = orig_storage
                new_ex.balance = orig_balance

            # add to worklist
            new_ex.next_pc()
            stack.append((new_ex, step_id))

    def jumpi(
        self,
        ex: Exec,
        stack: List[Tuple[Exec, int]],
        step_id: int,
        logs: HalmosLogs,
    ) -> None:
        jid = ex.jumpi_id()

        source: int = ex.pc
        target: int = int_of(ex.st.pop(), "symbolic JUMPI target")
        cond: Word = ex.st.pop()

        visited = ex.jumpis.get(jid, {True: 0, False: 0})

        cond_true = simplify(is_non_zero(cond))
        cond_false = simplify(is_zero(cond))

        potential_true: bool = ex.check(cond_true) != unsat
        potential_false: bool = ex.check(cond_false) != unsat

        # note: both may be false if the previous path condition was considered unknown but turns out to be unsat later

        follow_true = False
        follow_false = False

        if potential_true and potential_false:
            # for loop unrolling
            follow_true = visited[True] < self.options["max_loop"]
            follow_false = visited[False] < self.options["max_loop"]
            if not (follow_true and follow_false):
                logs.bounded_loops.append(jid)
        else:
            # for constant-bounded loops
            follow_true = potential_true
            follow_false = potential_false

        new_ex_true = None
        new_ex_false = None

        if follow_true:
            if follow_false:
                new_ex_true = self.create_branch(ex, cond_true, target)
            else:
                new_ex_true = ex
                new_ex_true.solver.add(cond_true)
                new_ex_true.path.append(str(cond_true))
                new_ex_true.pc = target

        if follow_false:
            new_ex_false = ex
            new_ex_false.solver.add(cond_false)
            new_ex_false.path.append(str(cond_false))
            new_ex_false.next_pc()

        if new_ex_true:
            if potential_true and potential_false:
                new_ex_true.jumpis[jid] = {
                    True: visited[True] + 1,
                    False: visited[False],
                }
            stack.append((new_ex_true, step_id))

        if new_ex_false:
            if potential_true and potential_false:
                new_ex_false.jumpis[jid] = {
                    True: visited[True],
                    False: visited[False] + 1,
                }
            stack.append((new_ex_false, step_id))

    def jump(self, ex: Exec, stack: List[Tuple[Exec, int]], step_id: int) -> None:
        dst = ex.st.pop()

        # if dst is concrete, just jump
        if is_concrete(dst):
            ex.pc = int_of(dst)
            stack.append((ex, step_id))

        # otherwise, create a new execution for feasible targets
        elif self.options["sym_jump"]:
            for target in ex.pgm.valid_jump_destinations():
                target_reachable = simplify(dst == target)
                if ex.check(target_reachable) != unsat:  # jump
                    if self.options.get("debug"):
                        print(f"We can jump to {target} with model {ex.solver.model()}")
                    new_ex = self.create_branch(ex, target_reachable, target)
                    stack.append((new_ex, step_id))
        else:
            raise NotConcreteError(f"symbolic JUMP target: {dst}")

    def create_branch(self, ex: Exec, cond: BitVecRef, target: int) -> Exec:
        new_solver = create_solver(
            timeout=self.options["timeout"], max_memory=self.options["max_memory"]
        )
        new_solver.add(ex.solver.assertions())
        new_solver.add(cond)
        new_path = ex.path.copy()
        new_path.append(str(cond))
        new_ex = Exec(
            code=ex.code.copy(),  # shallow copy for potential new contract creation; existing code doesn't change
            storage=deepcopy(ex.storage),
            balance=ex.balance,
            #
            block=deepcopy(ex.block),
            #
            context=deepcopy(ex.context),
            this=ex.this,
            #
            pgm=ex.pgm,
            pc=target,
            st=deepcopy(ex.st),
            jumpis=deepcopy(ex.jumpis),
            symbolic=ex.symbolic,
            prank=deepcopy(ex.prank),
            #
            solver=new_solver,
            path=new_path,
            alias=ex.alias.copy(),
            #
            cnts=deepcopy(ex.cnts),
            sha3s=ex.sha3s.copy(),
            storages=ex.storages.copy(),
            balances=ex.balances.copy(),
            calls=ex.calls.copy(),
        )
        return new_ex

    def sym_byte_of(self, idx: BitVecRef, w: BitVecRef) -> BitVecRef:
        """generate symbolic BYTE opcode result using 32 nested ite"""

        def gen_nested_ite(curr: int) -> BitVecRef:
            if curr < 32:
                return If(
                    idx == con(curr),
                    Extract((31 - curr) * 8 + 7, (31 - curr) * 8, w),
                    gen_nested_ite(curr + 1),
                )
            else:
                return con(0, 8)

        # If(idx == 0, Extract(255, 248, w), If(idx == 1, Extract(247, 240, w), ..., If(idx == 31, Extract(7, 0, w), 0)...))
        return ZeroExt(248, gen_nested_ite(0))

    def run(self, ex0: Exec) -> Tuple[List[Exec], Steps, HalmosLogs]:
        out: List[Exec] = []
        logs = HalmosLogs()
        steps: Steps = {}
        step_id: int = 0

        stack: List[Tuple[Exec, int]] = [(ex0, 0)]
        while stack:
            try:
                if len(out) >= self.options.get("max_width", 2**64):
                    break

                (ex, prev_step_id) = stack.pop()
                step_id += 1

                if ex.context.depth > MAX_CALL_DEPTH:
                    raise MessageDepthLimitError(ex.context)

                insn = ex.current_instruction()
                opcode = insn.opcode
                ex.cnts["opcode"][opcode] += 1

                if (
                    "max_depth" in self.options
                    and sum(ex.cnts["opcode"].values()) > self.options["max_depth"]
                ):
                    continue

                if self.options.get("log"):
                    if opcode == EVM.JUMPI:
                        steps[step_id] = {"parent": prev_step_id, "exec": str(ex)}
                    # elif opcode == EVM.CALL:
                    #     steps[step_id] = {'parent': prev_step_id, 'exec': str(ex) + ex.st.str_memory() + '\n'}
                    else:
                        # steps[step_id] = {'parent': prev_step_id, 'exec': ex.summary()}
                        steps[step_id] = {"parent": prev_step_id, "exec": str(ex)}

                if self.options.get("print_steps"):
                    print(ex)

                if opcode == EVM.STOP:
                    ex.halt()
                    out.append(ex)
                    continue

                elif opcode == EVM.INVALID:
                    ex.halt(error=InvalidOpcode(opcode))
                    out.append(ex)
                    continue

                elif opcode == EVM.REVERT:
                    ex.halt(data=ex.st.ret(), error=Revert())
                    out.append(ex)
                    continue

                elif opcode == EVM.RETURN:
                    ex.halt(data=ex.st.ret())
                    out.append(ex)
                    continue

                elif opcode == EVM.JUMPI:
                    self.jumpi(ex, stack, step_id, logs)
                    continue

                elif opcode == EVM.JUMP:
                    self.jump(ex, stack, step_id)
                    continue

                elif opcode == EVM.JUMPDEST:
                    pass

                elif EVM.ADD <= opcode <= EVM.SMOD:  # ADD MUL SUB DIV SDIV MOD SMOD
                    ex.st.push(self.arith(ex, opcode, ex.st.pop(), ex.st.pop()))

                elif EVM.ADDMOD <= opcode <= EVM.MULMOD:  # ADDMOD MULMOD
                    ex.st.push(
                        self.arith2(ex, opcode, ex.st.pop(), ex.st.pop(), ex.st.pop())
                    )

                elif opcode == EVM.EXP:
                    ex.st.push(self.arith(ex, opcode, ex.st.pop(), ex.st.pop()))

                elif opcode == EVM.LT:
                    w1 = b2i(ex.st.pop())
                    w2 = b2i(ex.st.pop())
                    ex.st.push(ULT(w1, w2))  # bvult
                elif opcode == EVM.GT:
                    w1 = b2i(ex.st.pop())
                    w2 = b2i(ex.st.pop())
                    ex.st.push(UGT(w1, w2))  # bvugt
                elif opcode == EVM.SLT:
                    w1 = b2i(ex.st.pop())
                    w2 = b2i(ex.st.pop())
                    ex.st.push(w1 < w2)  # bvslt
                elif opcode == EVM.SGT:
                    w1 = b2i(ex.st.pop())
                    w2 = b2i(ex.st.pop())
                    ex.st.push(w1 > w2)  # bvsgt

                elif opcode == EVM.EQ:
                    w1 = ex.st.pop()
                    w2 = ex.st.pop()
                    if eq(w1.sort(), w2.sort()):
                        ex.st.push(w1 == w2)
                    else:
                        if is_bool(w1):
                            if not is_bv(w2):
                                raise ValueError(w2)
                            ex.st.push(If(w1, con(1), con(0)) == w2)
                        else:
                            if not is_bv(w1):
                                raise ValueError(w1)
                            if not is_bool(w2):
                                raise ValueError(w2)
                            ex.st.push(w1 == If(w2, con(1), con(0)))
                elif opcode == EVM.ISZERO:
                    ex.st.push(is_zero(ex.st.pop()))

                elif opcode in [EVM.AND, EVM.OR, EVM.XOR]:
                    ex.st.push(bitwise(opcode, ex.st.pop(), ex.st.pop()))
                elif opcode == EVM.NOT:
                    ex.st.push(~b2i(ex.st.pop()))  # bvnot
                elif opcode == EVM.SHL:
                    w = ex.st.pop()
                    ex.st.push(b2i(ex.st.pop()) << b2i(w))  # bvshl
                elif opcode == EVM.SAR:
                    w = ex.st.pop()
                    ex.st.push(ex.st.pop() >> w)  # bvashr
                elif opcode == EVM.SHR:
                    w = ex.st.pop()
                    ex.st.push(LShR(ex.st.pop(), w))  # bvlshr

                elif opcode == EVM.SIGNEXTEND:
                    w = int_of(ex.st.pop(), "symbolic SIGNEXTEND size")
                    if w <= 30:  # if w == 31, result is SignExt(0, value) == value
                        bl = (w + 1) * 8
                        ex.st.push(SignExt(256 - bl, Extract(bl - 1, 0, ex.st.pop())))

                elif opcode == EVM.CALLDATALOAD:
                    calldata = ex.calldata()
                    if calldata is None:
                        ex.st.push(f_calldataload(ex.st.pop()))
                    else:
                        err_msg = "symbolic CALLDATALOAD offset"
                        offset: int = int_of(ex.st.pop(), err_msg)
                        data = padded_slice(calldata, offset, 32, default=con(0, 8))
                        ex.st.push(Concat(data))

                elif opcode == EVM.CALLDATASIZE:
                    cd = ex.calldata()

                    # TODO: is optional calldata necessary?
                    ex.st.push(f_calldatasize() if cd is None else con(len(cd)))

                elif opcode == EVM.CALLVALUE:
                    ex.st.push(ex.callvalue())
                elif opcode == EVM.CALLER:
                    ex.st.push(uint256(ex.caller()))
                elif opcode == EVM.ORIGIN:
                    ex.st.push(uint256(f_origin()))
                elif opcode == EVM.ADDRESS:
                    ex.st.push(uint256(ex.this))
                # TODO: define f_extcodesize for known addresses in advance
                elif opcode == EVM.EXTCODESIZE:
                    account = uint160(ex.st.pop())
                    account_addr = self.resolve_address_alias(ex, account)
                    if account_addr is not None:
                        codesize = con(len(ex.code[account_addr]))
                    else:
                        codesize = f_extcodesize(account)
                        if (
                            eq(account, hevm_cheat_code.address)
                            or eq(account, halmos_cheat_code.address)
                            or eq(account, console.address)
                        ):
                            ex.solver.add(codesize > 0)
                    ex.st.push(codesize)
                # TODO: define f_extcodehash for known addresses in advance
                elif opcode == EVM.EXTCODEHASH:
                    account = uint160(ex.st.pop())
                    account_addr = self.resolve_address_alias(ex, account)
                    codehash = (
                        f_extcodehash(account_addr)
                        if account_addr is not None
                        else f_extcodehash(account)
                    )
                    ex.st.push(codehash)
                elif opcode == EVM.CODESIZE:
                    ex.st.push(con(len(ex.pgm)))
                elif opcode == EVM.GAS:
                    ex.st.push(f_gas(con(ex.new_gas_id())))
                elif opcode == EVM.GASPRICE:
                    ex.st.push(f_gasprice())

                elif opcode == EVM.BASEFEE:
                    ex.st.push(ex.block.basefee)
                elif opcode == EVM.CHAINID:
                    ex.st.push(ex.block.chainid)
                elif opcode == EVM.COINBASE:
                    ex.st.push(uint256(ex.block.coinbase))
                elif opcode == EVM.DIFFICULTY:
                    ex.st.push(ex.block.difficulty)
                elif opcode == EVM.GASLIMIT:
                    ex.st.push(ex.block.gaslimit)
                elif opcode == EVM.NUMBER:
                    ex.st.push(ex.block.number)
                elif opcode == EVM.TIMESTAMP:
                    ex.st.push(ex.block.timestamp)

                elif opcode == EVM.PC:
                    ex.st.push(con(ex.pc))

                elif opcode == EVM.BLOCKHASH:
                    ex.st.push(f_blockhash(ex.st.pop()))

                elif opcode == EVM.BALANCE:
                    ex.st.push(ex.balance_of(uint160(ex.st.pop())))
                elif opcode == EVM.SELFBALANCE:
                    ex.st.push(ex.balance_of(ex.this))

                elif opcode in [
                    EVM.CALL,
                    EVM.CALLCODE,
                    EVM.DELEGATECALL,
                    EVM.STATICCALL,
                ]:
                    self.call(ex, opcode, stack, step_id, out, logs)
                    continue

                elif opcode == EVM.SHA3:
                    ex.sha3()

                elif opcode in [EVM.CREATE, EVM.CREATE2]:
                    self.create(ex, opcode, stack, step_id, out, logs)
                    continue

                elif opcode == EVM.POP:
                    ex.st.pop()
                elif opcode == EVM.MLOAD:
                    ex.st.mload()
                elif opcode == EVM.MSTORE:
                    ex.st.mstore(True)
                elif opcode == EVM.MSTORE8:
                    ex.st.mstore(False)

                elif opcode == EVM.MSIZE:
                    size: int = len(ex.st.memory)
                    # round up to the next multiple of 32
                    size = ((size + 31) // 32) * 32
                    ex.st.push(con(size))

                elif opcode == EVM.SLOAD:
                    ex.st.push(self.sload(ex, ex.this, ex.st.pop()))
                elif opcode == EVM.SSTORE:
                    self.sstore(ex, ex.this, ex.st.pop(), ex.st.pop())

                elif opcode == EVM.RETURNDATASIZE:
                    ex.st.push(con(ex.returndatasize()))
                elif opcode == EVM.RETURNDATACOPY:
                    loc: int = ex.st.mloc()
                    offset: int = int_of(ex.st.pop(), "symbolic RETURNDATACOPY offset")
                    # size (in bytes)
                    size: int = int_of(ex.st.pop(), "symbolic RETURNDATACOPY size")

                    # TODO: do we need to pass returndatasize here?
                    wstore_partial(
                        ex.st.memory,
                        loc,
                        offset,
                        size,
                        ex.returndata(),
                        ex.returndatasize(),
                    )

                elif opcode == EVM.CALLDATACOPY:
                    loc: int = ex.st.mloc()
                    offset: int = int_of(ex.st.pop(), "symbolic CALLDATACOPY offset")
                    # size (in bytes)
                    size: int = int_of(ex.st.pop(), "symbolic CALLDATACOPY size")
                    if size > 0:
                        calldata = ex.message().data
                        if calldata is None:
                            f_calldatacopy = Function(
                                "calldatacopy_" + str(size * 8),
                                BitVecSort256,
                                BitVecSorts[size * 8],
                            )
                            data = f_calldatacopy(offset)
                            wstore(ex.st.memory, loc, size, data)
                        else:
                            data = padded_slice(calldata, offset, size, con(0, 8))
                            wstore_bytes(ex.st.memory, loc, size, data)

                elif opcode == EVM.CODECOPY:
                    loc: int = ex.st.mloc()
                    offset: int = int_of(ex.st.pop(), "symbolic CODECOPY offset")
                    # size (in bytes)
                    size: int = int_of(ex.st.pop(), "symbolic CODECOPY size")
                    wextend(ex.st.memory, loc, size)

                    codeslice = ex.pgm[offset : offset + size]

                    actual_size = byte_length(codeslice)
                    if actual_size != size:
                        raise HalmosException(
                            f"CODECOPY: expected {size} bytes but got {actual_size}"
                        )

                    ex.st.memory[loc : loc + size] = iter_bytes(codeslice)

                elif opcode == EVM.BYTE:
                    idx = ex.st.pop()
                    w = ex.st.pop()
                    if is_bv_value(idx):
                        idx = idx.as_long()
                        if idx < 0:
                            raise ValueError(idx)
                        if idx >= 32:
                            ex.st.push(con(0))
                        else:
                            ex.st.push(
                                ZeroExt(
                                    248, Extract((31 - idx) * 8 + 7, (31 - idx) * 8, w)
                                )
                            )
                    else:
                        if self.options["debug"]:
                            print(
                                f"Warning: the use of symbolic BYTE indexing may potentially impact the performance of symbolic reasoning: BYTE {idx} {w}"
                            )
                        ex.st.push(self.sym_byte_of(idx, w))

                elif EVM.LOG0 <= opcode <= EVM.LOG4:
                    if ex.message().is_static:
                        raise WriteInStaticContext(ex.context_str())

                    num_topics: int = opcode - EVM.LOG0
                    loc: int = ex.st.mloc()
                    size: int = int_of(ex.st.pop(), "symbolic LOG data size")
                    topics = list(ex.st.pop() for _ in range(num_topics))
                    data = wload(ex.st.memory, loc, size) if size > 0 else None

                    ex.emit_log(EventLog(ex.this, topics, data))

                elif opcode == EVM.PUSH0:
                    ex.st.push(con(0))

                elif EVM.PUSH1 <= opcode <= EVM.PUSH32:
                    if is_concrete(insn.operand):
                        val = int_of(insn.operand)
                        if opcode == EVM.PUSH32 and val in sha3_inv:
                            # restore precomputed hashes
                            ex.st.push(ex.sha3_data(con(sha3_inv[val]), 32))
                        else:
                            ex.st.push(con(val))
                    else:
                        if opcode == EVM.PUSH32:
                            ex.st.push(insn.operand)
                        else:
                            ex.st.push(ZeroExt((EVM.PUSH32 - opcode) * 8, insn.operand))
                elif EVM.DUP1 <= opcode <= EVM.DUP16:
                    ex.st.dup(opcode - EVM.DUP1 + 1)
                elif EVM.SWAP1 <= opcode <= EVM.SWAP16:
                    ex.st.swap(opcode - EVM.SWAP1 + 1)

                else:
                    # TODO: switch to InvalidOpcode when we have full opcode coverage
                    # this halts the path, but we should only halt the current context
                    raise HalmosException(f"Unsupported opcode {hex(opcode)}")

                ex.next_pc()
                stack.append((ex, step_id))

            except EvmException as err:
                ex.halt(error=err)
                out.append(ex)
                continue

            except HalmosException as err:
                if self.options["debug"]:
                    print(err)
                ex.halt(data=None, error=err)
                out.append(ex)
                continue

        return (out, steps, logs)

    def mk_exec(
        self,
        #
        code,
        storage,
        balance,
        #
        block,
        #
        context: CallContext,
        #
        this,
        #
        pgm,
        symbolic,
        solver,
    ) -> Exec:
        return Exec(
            code=code,
            storage=storage,
            balance=balance,
            #
            block=block,
            #
            context=context,
            #
            this=this,
            pgm=pgm,
            pc=0,
            st=State(),
            jumpis={},
            symbolic=symbolic,
            prank=Prank(),
            #
            solver=solver,
            path=[],
            alias={},
            #
            log=[],
            cnts=defaultdict(lambda: defaultdict(int)),
            sha3s={},
            storages={},
            balances={},
            calls=[],
        )
