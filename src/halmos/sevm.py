# SPDX-License-Identifier: AGPL-3.0

import itertools
import re
from collections import Counter, defaultdict
from collections.abc import Callable, Iterator
from copy import deepcopy
from dataclasses import dataclass, field
from datetime import timedelta
from functools import reduce
from timeit import default_timer as timer
from typing import (
    Any,
    ForwardRef,
    Optional,
    TypeAlias,
    TypeVar,
    Union,
)

import xxhash
from eth_hash.auto import keccak
from z3 import (
    UGE,
    ULE,
    ULT,
    And,
    Array,
    ArrayRef,
    BitVec,
    BitVecRef,
    BoolRef,
    BoolVal,
    CheckSatResult,
    Concat,
    Context,
    Extract,
    Function,
    If,
    Not,
    Select,
    Solver,
    Store,
    ZeroExt,
    eq,
    is_const,
    is_eq,
    is_false,
    is_true,
    sat,
    simplify,
    unsat,
)
from z3.z3util import is_expr_var

from halmos.bitvec import ONE, ZERO, is_power_of_two
from halmos.bitvec import HalmosBitVec as BV
from halmos.bitvec import HalmosBool as Bool
from halmos.bytevec import ByteVec, SymbolicChunk
from halmos.calldata import FunctionInfo
from halmos.cheatcodes import Prank, halmos_cheat_code, hevm_cheat_code
from halmos.config import Config as HalmosConfig
from halmos.console import console
from halmos.constants import MAX_ETH, MAX_MEMORY_SIZE
from halmos.contract import (
    CALL_OPCODES,
    CREATE_OPCODES,
    OP_ADD,
    OP_ADDMOD,
    OP_ADDRESS,
    OP_AND,
    OP_BALANCE,
    OP_BASEFEE,
    OP_BLOCKHASH,
    OP_BYTE,
    OP_CALL,
    OP_CALLDATACOPY,
    OP_CALLDATALOAD,
    OP_CALLDATASIZE,
    OP_CALLER,
    OP_CALLVALUE,
    OP_CHAINID,
    OP_CODECOPY,
    OP_CODESIZE,
    OP_COINBASE,
    OP_CREATE,
    OP_CREATE2,
    OP_DELEGATECALL,
    OP_DIFFICULTY,
    OP_DIV,
    OP_DUP1,
    OP_DUP16,
    OP_EQ,
    OP_EXP,
    OP_EXTCODECOPY,
    OP_EXTCODEHASH,
    OP_EXTCODESIZE,
    OP_GAS,
    OP_GASLIMIT,
    OP_GASPRICE,
    OP_GT,
    OP_INVALID,
    OP_ISZERO,
    OP_JUMP,
    OP_JUMPDEST,
    OP_JUMPI,
    OP_LOG0,
    OP_LOG4,
    OP_LT,
    OP_MCOPY,
    OP_MLOAD,
    OP_MOD,
    OP_MSIZE,
    OP_MSTORE,
    OP_MSTORE8,
    OP_MUL,
    OP_MULMOD,
    OP_NOT,
    OP_NUMBER,
    OP_OR,
    OP_ORIGIN,
    OP_PC,
    OP_POP,
    OP_PUSH0,
    OP_PUSH1,
    OP_PUSH31,
    OP_PUSH32,
    OP_RETURN,
    OP_RETURNDATACOPY,
    OP_RETURNDATASIZE,
    OP_REVERT,
    OP_SAR,
    OP_SDIV,
    OP_SELFBALANCE,
    OP_SGT,
    OP_SHA3,
    OP_SHL,
    OP_SHR,
    OP_SIGNEXTEND,
    OP_SLOAD,
    OP_SLT,
    OP_SMOD,
    OP_SSTORE,
    OP_STATICCALL,
    OP_STOP,
    OP_SUB,
    OP_SWAP1,
    OP_SWAP16,
    OP_TIMESTAMP,
    OP_TLOAD,
    OP_TSTORE,
    OP_XOR,
    TERMINATING_OPCODES,
    Contract,
    CoverageReporter,
    Instruction,
    mnemonic,
)
from halmos.exceptions import (
    AddressCollision,
    EvmException,
    FailCheatcode,
    HalmosException,
    InfeasiblePath,
    InsufficientFunds,
    InvalidJumpDestError,
    InvalidOpcode,
    MessageDepthLimitError,
    NotConcreteError,
    OutOfBoundsRead,
    OutOfGasError,
    PathEndingException,
    Revert,
    StackUnderflowError,
    WriteInStaticContext,
)
from halmos.logs import (
    INTERNAL_ERROR,
    debug,
    debug_once,
    warn,
    warn_code,
)
from halmos.mapper import BuildOut
from halmos.ui import ui
from halmos.utils import (
    Address,
    BitVecSort160,
    BitVecSort256,
    BitVecSort264,
    BitVecSort512,
    BitVecSorts,
    Byte,
    Bytes,
    OffsetMap,
    Word,
    assert_address,
    assert_bv,
    bv_value_to_bytes,
    byte_length,
    bytes_to_bv_value,
    con,
    con_addr,
    concat,
    create_solver,
    f_ecrecover,
    f_inv_sha3_name,
    f_inv_sha3_size,
    f_sha3_256_name,
    f_sha3_512_name,
    f_sha3_empty,
    f_sha3_name,
    hexify,
    int_of,
    is_bool,
    is_bv,
    is_bv_value,
    is_f_sha3_name,
    match_dynamic_array_overflow_condition,
    precomputed_keccak_registry,
    stripped,
    uid,
    uint8,
    uint160,
    uint256,
    unbox_int,
)

EMPTY_BYTES = ByteVec()
EMPTY_KECCAK = 0xC5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470
Z3_ZERO, Z3_ONE = con(0), con(1)
MAX_CALL_DEPTH = 1024

# Precompile addresses
ECRECOVER_PRECOMPILE = BV(1, size=160)
SHA256_PRECOMPILE = BV(2, size=160)
RIPEMD160_PRECOMPILE = BV(3, size=160)
IDENTITY_PRECOMPILE = BV(4, size=160)
MODEXP_PRECOMPILE = BV(5, size=160)
ECADD_PRECOMPILE = BV(6, size=160)
ECMUL_PRECOMPILE = BV(7, size=160)
ECPAIRING_PRECOMPILE = BV(8, size=160)
BLAKE2F_PRECOMPILE = BV(9, size=160)
POINT_EVALUATION_PRECOMPILE = BV(10, size=160)
# bytes4(keccak256("Panic(uint256)"))
PANIC_SELECTOR = bytes.fromhex("4E487B71")

EMPTY_BALANCE = Array("balance_00", BitVecSort160, BitVecSort256)

# TODO: make this configurable
PULSE_INTERVAL = 2**13
assert is_power_of_two(PULSE_INTERVAL)

# NOTE: `con_addr()` wrapper is needed for FOUNDRY_TEST, which will be used as a key for ex.code,
# and compared for structural equality with other BitVecRef addresses.
FOUNDRY_TEST = con_addr(0x7FA9385BE102AC3EAC297483DD6233D62B3E1496)
FOUNDRY_CALLER = 0x1804C8AB1F12E6BBF3894D4083F33E07309D1F38
FOUNDRY_ORIGIN = FOUNDRY_CALLER

CHEATCODE_ADDRESSES: tuple[BV, ...] = (
    hevm_cheat_code.address,
    halmos_cheat_code.address,
    console.address,
)


# (pc, (jumpdest, ...))
# the jumpdests are stored as strings to avoid the cost of converting bv values
JumpID = tuple[int, tuple[str]]

# symbolic states

# blockhash(block number)
f_blockhash = Function("f_blockhash", BitVecSort256, BitVecSort256)
# gas(cnt)
f_gas = Function("f_gas", BitVecSort256, BitVecSort256)
# gasprice()
f_gasprice = Function("f_gasprice", BitVecSort256)

# uninterpreted arithmetic
f_div = Function("f_evm_bvudiv_256", BitVecSort256, BitVecSort256, BitVecSort256)
f_mod = {
    256: Function("f_evm_bvurem_256", BitVecSort256, BitVecSort256, BitVecSort256),
    264: Function("f_evm_bvurem_264", BitVecSort264, BitVecSort264, BitVecSort264),
    512: Function("f_evm_bvurem_512", BitVecSort512, BitVecSort512, BitVecSort512),
}
f_mul = {
    256: Function("f_evm_bvmul_256", BitVecSort256, BitVecSort256, BitVecSort256),
    512: Function("f_evm_bvmul_512", BitVecSort512, BitVecSort512, BitVecSort512),
}
f_sdiv = Function("f_evm_bvsdiv_256", BitVecSort256, BitVecSort256, BitVecSort256)
f_smod = Function("f_evm_bvsrem_256", BitVecSort256, BitVecSort256, BitVecSort256)
f_exp = Function("f_evm_exp_256", BitVecSort256, BitVecSort256, BitVecSort256)

magic_address: int = 0xAAAA0000

create2_magic_address: int = 0xBBBB0000

new_address_offset: int = 1


def jumpid_str(jumpid: JumpID) -> str:
    pc, jumpdests = jumpid
    return f"{pc}:{','.join(str(j) for j in jumpdests)}"


def id_str(x: Any) -> str:
    return hexify(x).replace(" ", "")


def normalize(expr: Any) -> Any:
    # Concat(Extract(255, 8, op(x, y)), op(Extract(7, 0, x), Extract(7, 0, y))) => op(x, y)
    def normalize_extract(arg0, arg1):
        if (
            arg0.decl().name() == "extract"
            and arg0.num_args() == 1
            and arg0.params() == [255, 8]
        ):
            target = arg0.arg(0)  # op(x, y)

            # this form triggers the partial inward-propagation of extracts in simplify()
            # that is, `Extract(7, 0, op(x, y))` => `op(Extract(7, 0, x), Extract(7, 0, y))`, followed by further simplification
            target_equivalent = Concat(Extract(255, 8, target), Extract(7, 0, target))

            given = Concat(arg0, arg1)

            # since target_equivalent and given may not be structurally equal, we compare their fully simplified forms
            if eq(simplify(given), simplify(target_equivalent)):
                # here we have: given == target_equivalent == target
                return target

        return None

    if expr.decl().name() == "concat" and expr.num_args() >= 2:
        new_args = []

        i = 0
        n = expr.num_args()

        # apply normalize_extract for each pair of adjacent arguments
        while i < n - 1:
            arg0 = expr.arg(i)
            arg1 = expr.arg(i + 1)

            arg0_arg1 = normalize_extract(arg0, arg1)

            if arg0_arg1 is None:  # not simplified
                new_args.append(arg0)
                i += 1
            else:  # simplified into a single term
                new_args.append(arg0_arg1)
                i += 2

        # handle the last element
        if i == n - 1:
            new_args.append(expr.arg(i))

        return concat(new_args)

    return expr


def copy_returndata_to_memory(
    returndata: ByteVec, ret_loc: int, ret_size: int, ex: ForwardRef("Exec")
) -> None:
    """
    Copy the return data from an external call to the memory of the caller.

    Args:
        returndata: the return data from the external call
        ret_loc: the location in the memory of the caller to write the return data to
                 (specified by the *CALL instruction)
        ret_size: the size of the return data to write to memory
                  (specified by the *CALL instruction)
        ex: the execution context of the caller

    Note that if the return data is smaller than the requested size,
    only the actual size of the return data is written to memory and the
    rest of the memory is not modified.
    """

    actual_ret_size = len(returndata)
    effective_ret_size = min(ret_size, actual_ret_size)

    if not effective_ret_size:
        return

    # fast path: if the requested ret_size is the actual size of the return data,
    # we can skip the slice (copy) operation and directly write the return data to memory
    data = (
        returndata.slice(0, effective_ret_size)
        if effective_ret_size < actual_ret_size
        else returndata
    )

    ex.st.set_mslice(ret_loc, data)


@dataclass(frozen=True, slots=True, eq=False, order=False)
class EventLog:
    """
    Data record produced during the execution of a transaction.
    """

    address: Address
    topics: list[Word]
    data: "Bytes | None"


@dataclass(frozen=True, slots=True, eq=False, order=False)
class StorageWrite:
    address: Address
    slot: Word
    value: Word
    transient: bool


@dataclass(frozen=True, slots=True, eq=False, order=False)
class StorageRead:
    address: Address
    slot: Word
    value: Word
    transient: bool


@dataclass(frozen=True, slots=True, eq=False, order=False)
class Message:
    target: Address
    caller: Address
    origin: Address
    value: Word
    data: ByteVec

    # we outer calls, we expect a virtual call scheme to be provided, either CREATE or CALL
    call_scheme: int

    is_static: bool = False
    gas: Word | None = None

    # optional human-readable function information (name, signature, selector, etc.)
    fun_info: FunctionInfo | None = None

    def is_create(self) -> bool:
        return self.call_scheme in (OP_CREATE, OP_CREATE2)

    def calldata_slice(self, start: int, size: int) -> ByteVec:
        """Wrapper around calldata access with a size check."""
        if size > MAX_MEMORY_SIZE:
            raise OutOfGasError(f"calldata read {start=} {size=} > MAX_MEMORY_SIZE")

        return self.data.slice(start=start, stop=start + size)


@dataclass(frozen=False, slots=True, eq=False, order=False)
class CallOutput:
    """
    Data record produced during the execution of a call.
    """

    data: ByteVec | None = None
    accounts_to_delete: set[Address] = field(default_factory=set)
    error: EvmException | HalmosException | None = None
    return_scheme: int | None = None

    # TODO:
    #   - touched_accounts
    # not modeled:
    #   - gas_refund
    #   - gas_left

    def is_panic_of(self, expected_error_codes: set[int]) -> bool:
        """
        Check if the error is Panic(k) for any k in the given error code set.
        An empty set or None will match any error code.

        Panic(k) is encoded as 36 bytes (4 + 32) consisting of:
            bytes4(keccak256("Panic(uint256)")) + bytes32(k)
        """
        if not isinstance(self.error, Revert):
            return False

        error_data = self.data
        if byte_length(error_data) != 36:
            return False

        error_selector = error_data[0:4].unwrap()
        if error_selector != PANIC_SELECTOR:
            return False

        # match any error code
        if not expected_error_codes:
            return True

        # the argument of Panic is expected to be concrete
        # NOTE: symbolic error code will be silently ignored
        error_code = unbox_int(error_data[4:36].unwrap())
        return error_code in expected_error_codes


TraceElement = Union["CallContext", EventLog, StorageRead, StorageWrite]


# TODO: support frozen=True
@dataclass(frozen=False, slots=True, eq=False, order=False)
class CallContext:
    """
    Represents a single, atomic call to an address (typically a contract, but not necessarily).
    It is started by a Message, and has a mutable (initially empty) output.

    The trace field represents events that occurred during the execution of the call:
    - storage reads and writes
    - logs
    - subcalls (making this a recursive data structure)
    """

    message: Message
    output: CallOutput = field(default_factory=CallOutput)
    depth: int = 1
    trace: list[TraceElement] = field(default_factory=list)
    prank: Prank = field(default_factory=Prank)

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
        data, error = self.output.data, self.output.error
        return data is None or isinstance(error, HalmosException)

    def get_stuck_reason(self) -> HalmosException | None:
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


CallSequence: TypeAlias = list[CallContext]
"""
Represents a sequence of calls, from any senders to any addresses.

The order matters, because it represents a chronologic sequence of execution. That is to say,
the output state of one call is the input state of the next call in the sequence.
"""


@dataclass(frozen=True, slots=True, eq=False, order=False)
class State:
    stack: list[Word] = field(default_factory=list)
    memory: ByteVec = field(default_factory=ByteVec)

    def __deepcopy__(self, memo):  # -> State:
        return State(stack=self.stack.copy(), memory=self.memory.copy())

    def dump(self, print_mem=False) -> str:
        if print_mem:
            return f"Stack: {str(list(reversed(self.stack)))}\n{self.str_memory()}"
        else:
            return f"Stack: {str(list(reversed(self.stack)))}"

    def __str__(self) -> str:
        return f"Stack: {str(list(reversed(self.stack)))}\n{self.str_memory()}"

    def str_memory(self) -> str:
        return (
            "Memory:"
            + "".join(
                f"\n- {idx:04x}: {hexify(self.memory.get_word(idx))}"
                for idx in range(0, len(self.memory), 32)
            )
            + "\n"
        )

    def push(self, v: Bool | BV) -> None:
        type_v = type(v)
        assert type_v is BV and v.size == 256 or type_v is Bool
        self.stack.append(v)

    def push_any(self, v: Any) -> None:
        # wraps any value in a 256-bit BitVec
        self.stack.append(BV(v, size=256))

    def set_top(self, v: Bool | BV) -> None:
        try:
            self.stack[-1] = v
        except IndexError as e:
            raise StackUnderflowError() from e

    def top(self) -> Bool | BV:
        """
        Returns the top element without popping it from the stack.
        """

        try:
            return self.stack[-1]
        except IndexError as e:
            raise StackUnderflowError() from e

    def topi(self) -> BV:
        """
        The stack can contain BitVecs or Bools -- this function converts Bools to BitVecs

        Returns the top element without popping it from the stack.
        """

        val = self.top()
        return val.as_bv(size=256) if type(val) is Bool else val

    def pop(self) -> Word:
        try:
            return self.stack.pop()
        except IndexError as e:
            raise StackUnderflowError() from e

    def popi(self) -> BV:
        """The stack can contain BitVecs or Bools -- this function converts Bools to BitVecs"""

        val = self.pop()
        return val.as_bv(size=256) if type(val) is Bool else val

    def peek(self, n: int = 1) -> Word:
        try:
            return self.stack[-n]
        except IndexError as e:
            raise StackUnderflowError() from e

    def dup(self, n: int) -> None:
        try:
            self.stack.append(self.stack[-n])
        except IndexError as e:
            raise StackUnderflowError() from e

    def swap(self, n: int) -> None:
        try:
            stack = self.stack
            stack[-(n + 1)], stack[-1] = stack[-1], stack[-(n + 1)]
        except IndexError as e:
            raise StackUnderflowError() from e

    def mloc(self, subst: dict = None, check_size: bool = True) -> int:
        loc: int = int_of(self.popi(), "symbolic memory offset", subst)
        if check_size and loc > MAX_MEMORY_SIZE:
            raise OutOfGasError(f"memory {loc=} > MAX_MEMORY_SIZE")
        return loc

    def mslice(self, loc: int, size: int) -> ByteVec:
        """Wraps a memory slice read with a size check."""

        if not size:
            return ByteVec()

        stop = loc + size
        if stop > MAX_MEMORY_SIZE:
            raise OutOfGasError(f"memory read {loc=} {size=} > MAX_MEMORY_SIZE")

        return self.memory.slice(start=loc, stop=stop)

    def set_mslice(self, loc: int, data: ByteVec) -> None:
        """Wraps a memory slice write with a size check."""

        size = len(data)

        if not size:
            return

        stop = loc + size
        if stop > MAX_MEMORY_SIZE:
            raise OutOfGasError(f"memory write {loc=} {size=} > MAX_MEMORY_SIZE")

        self.memory.set_slice(start=loc, stop=stop, value=data)

    def ret(self, subst: dict = None) -> ByteVec:
        loc: int = self.mloc(subst)
        size: int = int_of(self.popi(), "symbolic return data size", subst)

        return self.mslice(loc, size)


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


@dataclass(frozen=True)
class SMTQuery:
    smtlib: str
    assertions: list  # list of assertion ids


@dataclass(frozen=True)
class Concretization:
    """
    Mapping of terms to concrete values, and of symbols to potential candidates.

    A term is mapped to a concrete value when an equality between them is introduced in the path condition.
    These terms can be replaced by their concrete values during execution as needed.
    Note that cyclic substitutions do not occur, as terms are reduced to a ground value rather than another term.

    A symbol may also be associated with multiple concrete value candidates.
    If necessary, the path can later branch for each candidate.

    TODO: Currently, the branching mechanism based on candidates is only applied to calldata with dynamic parameters.
    In the future, it may be used for other purposes.
    """

    # term -> constant
    substitution: dict[BitVecRef, BitVecRef] = field(default_factory=dict)
    # symbol -> set of constants
    candidates: dict[BitVecRef, list[int]] = field(default_factory=dict)

    def process_cond(self, cond):
        if not is_eq(cond):
            return
        left, right = cond.arg(0), cond.arg(1)
        if is_bv_value(right):  # not is_bv_value(left)
            self.substitution[left] = right
        elif is_bv_value(left):  # not is_bv_value(right)
            self.substitution[right] = left

    def process_dyn_params(self, dyn_params):
        for d in dyn_params:
            self.candidates[d.size_symbol] = d.size_choices


class HashableTerm:
    """
    Thin wrapper around BitVecRef, ensuring that __eq__() returns bool instead of BoolRef.

    This allows BitVecRef to be used as dict keys without issues related to generating equality constraints between non-comparable terms.
    """

    def __init__(self, term: BitVecRef):
        self.term = term

    def __eq__(self, other) -> bool:
        """Checks structural equality instead of generating an equality constraint."""
        return self.term.eq(other.term)

    def __hash__(self):
        return hash(self.term)


class Path:
    """
    A Path object represents a prefix of the path currently being executed, where a path is defined by a sequence of branching conditions.
    A path may span internal contract calls and multiple transactions.

    In addition to branching conditions, a Path object also maintains additional constraints over symbolic values, such as implicit assumptions like no hash collisions.

    The `conditions` attribute contains both branching conditions and additional constraints.

    The `solver` attribute is a Z3 Solver object that essentially mirrors the `conditions` attribute.
    The Z3 solver is used to check whether a new branching condition is satisfiable, filtering out infeasible paths.

    For regular tests, `solver` contains all constraints from `conditions`.
    For invariant tests, however, `solver` excludes certain irrelevant constraints from `conditions`.
    Specifically, after executing each transaction, constraints related to state variables are identified and stored in the `sliced` attribute.
    Later, when a new Path object is created extending the previous path, only the `sliced` constraints are considered by the solver. This improves the performance of the solver as it handles fewer constraints.
    """

    solver: Solver
    num_scopes: int

    conditions: dict  # cond -> bool (true if explicit branching conditions)
    concretization: Concretization
    pending: list

    # a condition -> a set of previous conditions that are related to the condition
    related: dict[int, set[int]]
    # a variable -> a set of conditions in which the variable appears
    var_to_conds: dict[any, set[int]]
    # cache for get_var_set()
    term_to_vars: dict
    # constraints related to state variables
    sliced: set[int]

    def __init__(self, solver: Solver):
        self.solver = solver
        self.num_scopes = 0
        self.conditions = {}
        self.concretization = Concretization()
        self.pending = []

        self.related = {}
        self.var_to_conds = defaultdict(set)
        self.term_to_vars = {}
        self.sliced = None

    def _get_related(self, var_set) -> set[int]:
        conds = set()
        for var in var_set:
            conds.update(self.var_to_conds[var])

        result = set(conds)
        for cond in conds:
            result.update(self.related[cond])

        return result

    def get_related(self, cond) -> set[int]:
        return self._get_related(self.get_var_set(cond))

    def slice(self, var_set) -> None:
        if self.sliced is not None:
            raise ValueError("already sliced")

        self.sliced = self._get_related(var_set)

    def __deepcopy__(self, memo):
        raise NotImplementedError("use the branch() method instead of deepcopy()")

    def __str__(self) -> str:
        return (
            "".join(
                [
                    f"- {cond}\n"
                    for cond in self.conditions
                    if self.conditions[cond] and not is_true(cond)
                ]
            )
            or "- (empty path condition)"
        )

    def process_dyn_params(self, dyn_params):
        self.concretization.process_dyn_params(dyn_params)

    def to_smt2(self, args) -> SMTQuery:
        # Serialize self.conditions into the SMTLIB format.
        #
        # Each `c` in the conditions can be serialized to an SMTLIB assertion:
        #   `(assert c)`
        #
        # To compute the unsat-core later, a named assertion is needed:
        #   `(assert (! c :named id))` where `id` is the unique id of `c`
        #
        # However, z3.Solver.to_smt2() doesn't serialize into named assertions. Instead,
        # - `Solver.add(c)` is serialized as: `(assert c)`
        # - `Solver.assert_and_track(c, id)` is serialized as: `(assert (=> |id| c))`
        #
        # Thus, named assertions can be generated using `to_smt2()` as follows:
        # - add constraints using `assert_and_track(c, id)` for each c and id,
        # - execute `to_smt2()` to generate implication assertions, `(assert (=> |id| c))`, and
        # - generate named assertions, `(assert (! |id| :named <id>))`, for each id.
        #
        # The first two steps are performed here. The last step is done in `__main__.solve()`.
        #
        # NOTE: although both `to_smt2()` and `sexpr()` can generate SMTLIB assertions,
        #       sexpr()-generated SMTLIB queries are often less efficient to solve than to_smt2().
        #
        # TODO: leverage more efficient serialization by representing constraints in pickle-friendly objects, instead of Z3 objects.

        ids = [str(cond.get_id()) for cond in self.conditions]

        # TODO: investigate whether a separate context is necessary here
        tmp_solver = create_solver(ctx=Context())
        for cond in self.conditions:
            cond_copied = cond.translate(tmp_solver.ctx)
            if args.cache_solver:
                tmp_solver.assert_and_track(cond_copied, str(cond.get_id()))
            else:
                tmp_solver.add(cond_copied)
        # NOTE: Do not use self.solver.to_smt2() even if args.cache_solver is unset, as self.solver may not include all constraints from self.conditions.
        query = tmp_solver.to_smt2()
        tmp_solver.reset()

        query = query.replace("(check-sat)", "")  # see __main__.solve()

        return SMTQuery(query, ids)

    def check(self, cond):
        return self.solver.check(cond)

    def branch(self, cond):
        if len(self.pending) > 0:
            raise ValueError("branching from an inactive path", self)

        # create a new path that shares the same solver instance to minimize memory usage
        # note: sharing the solver instance complicates the use of randomized path exploration approaches, which can be more efficient for quickly finding bugs.
        # currently, a dfs-based path exploration is employed, which is suitable for scenarios where exploring all paths is necessary, e.g., when proving the absence of bugs.
        path = Path(self.solver)

        # print(f"path {id(path)} branched from {id(self)} with condition {cond}")

        # create a new scope within the solver, and save the current scope
        # the solver will roll back to this scope later when the new path is activated
        path.num_scopes = self.solver.num_scopes()

        # import threading
        # is_main_thread = threading.current_thread() == threading.main_thread()
        # print(f"[tid={hex(threading.get_ident())} {is_main_thread=}] pushing solver scope {path.solver.num_scopes()}")
        self.solver.push()

        # shallow copy because existing conditions won't change
        # note: deep copy would be needed later for advanced query optimizations (eg, constant propagation)
        path.conditions = self.conditions.copy()

        path.concretization = deepcopy(self.concretization)

        # store the branching condition aside until the new path is activated.
        path.pending.append(cond)

        # shallow copy because each entry references earlier entries thus remains unchanged later
        path.related = self.related.copy()
        path.var_to_conds = deepcopy(self.var_to_conds)
        # shared across different paths
        path.term_to_vars = self.term_to_vars
        # path.sliced = None

        return path

    def is_activated(self) -> bool:
        return len(self.pending) == 0

    def activate(self):
        if self.solver.num_scopes() < self.num_scopes:
            raise ValueError(
                "invalid num_scopes", self.solver.num_scopes(), self.num_scopes
            )

        self.solver.pop(self.solver.num_scopes() - self.num_scopes)

        self.extend(self.pending, branching=True)
        self.pending = []

    def collect_var_sets(self, hashable: HashableTerm):
        if hashable in self.term_to_vars:
            return

        result = set()

        term = hashable.term

        if is_const(term):
            if is_expr_var(term):
                result.add(term)

        else:
            for child in term.children():
                child = HashableTerm(child)
                self.collect_var_sets(child)
                result.update(self.term_to_vars[child])

        self.term_to_vars[hashable] = result

    def get_var_set(self, term: BitVecRef):
        term = HashableTerm(term)
        self.collect_var_sets(term)
        return self.term_to_vars[term]

    def append(self, cond: BoolRef, branching=False):
        cond = simplify(cond)

        if is_true(cond):
            return

        if is_false(cond):
            # false shouldn't have been added; raise InfeasiblePath before append() if false
            warn_code(INTERNAL_ERROR, "path.append(false)")

        if cond in self.conditions:
            return

        # determine the index for the new condition
        idx = len(self.conditions)

        self.solver.add(cond)
        self.conditions[cond] = branching
        self.concretization.process_cond(cond)

        # update dependency relation
        var_set = self.get_var_set(cond)
        self.related[idx] = self._get_related(var_set)
        for var in var_set:
            self.var_to_conds[var].add(idx)

    def extend(self, conds, branching=False):
        for cond in conds:
            self.append(cond, branching=branching)

    def extend_path(self, path):
        self.conditions = path.conditions.copy()
        self.concretization = deepcopy(path.concretization)
        self.related = path.related.copy()
        self.var_to_conds = deepcopy(path.var_to_conds)
        self.term_to_vars = path.term_to_vars

        # if the parent path is not sliced, then add all constraints to the solver
        if path.sliced is None:
            for cond in self.conditions:
                self.solver.add(cond)
            return

        # if the parent path is sliced, add only sliced constraints to the solver
        for idx, cond in enumerate(self.conditions):
            if idx in path.sliced:
                self.solver.add(cond)


class StorageData:
    def __init__(self):
        self.symbolic = False
        self._mapping = {}

    def __str__(self):
        return f"{self._mapping}"

    def __getitem__(self, key) -> ArrayRef | BitVecRef:
        return self._mapping[key]

    def __setitem__(self, key, value) -> None:
        self._mapping[key] = value

    def __contains__(self, key) -> bool:
        return key in self._mapping

    def digest(self) -> bytes:
        """
        Computes the xxh3_128 hash of the storage mapping.

        The hash input is constructed by serializing each key-value pair into a byte sequence.
        Keys are encoded as 256-bit integers for GenericStorage, or as arrays of 256-bit integers for SolidityStorage.
        Values, being Z3 objects, are encoded using their unique identifiers (get_id()) as 256-bit integers.
        For simplicity, all numbers are represented as 256-bit integers, regardless of their actual size.
        """
        m = xxhash.xxh3_128()
        # TODO: consider sorting items to ensure the digest is independent of the order of storage updates.
        for key, val in self._mapping.items():
            if isinstance(key, int):  # GenericStorage
                m.update(int.to_bytes(key, length=32))
            else:  # SolidityStorage
                for _k in key:
                    # The first key (slot) is of size 256 bits
                    m.update(int.to_bytes(_k, length=32))

            m.update(int.to_bytes(val.get_id(), length=32))
        return m.digest()


class KeccakRegistry:
    """A registry for tracking Keccak hash expressions and their corresponding values.

    This class provides a dict-like interface for backward compatibility,
    maintaining a mapping between hash expressions and their IDs (self._hash_ids).
    This was the original functionality used for storing hash expressions and their corresponding IDs.

    Additionally, this class provides an additional functionality for tracking
    hash expressions and their generating values using an OffsetMap (self._hash_values).
    This allows for reverse lookups to find the original expression that
    produced a given hash, even when the hash value is offset by some delta.
    This is particularly useful for:
    1. Local registry: Tracks hashes generated during execution
    2. Precomputed registry: Contains known/common hash expressions

    Example:
        registry = KeccakRegistry()

        # Registering a hash expression with an optional hash value
        registry.register(expr, hash_value)  # hash_value can be None

        # Getting unique ID for the hash expression
        id_value = registry.get_id(expr)

        # Checking if an expression is registered
        if expr in registry: ...

        # Reverse lookup of hash expressions
        original_expr = registry.reverse_lookup(hash_value)
        # With offset
        original_expr + delta = registry.reverse_lookup(hash_value + delta)
    """

    def __init__(self):
        self._hash_ids: dict[BitVecRef, int] = {}  # hash expr -> id
        self._hash_values = OffsetMap()  # hash value -> hash expr

    def get_id(self, expr: BitVecRef) -> int:
        return self._hash_ids[expr]

    def __contains__(self, expr: BitVecRef) -> bool:
        return expr in self._hash_ids

    def __iter__(self) -> Iterator[BitVecRef]:
        return iter(self._hash_ids)

    def copy(self) -> "KeccakRegistry":
        new_registry = KeccakRegistry()
        new_registry._hash_ids = self._hash_ids.copy()
        new_registry._hash_values = self._hash_values.copy()
        return new_registry

    def register(self, expr: BitVecRef, hash_value: bytes | None) -> None:
        if expr in self._hash_ids:
            return

        self._hash_ids[expr] = len(self._hash_ids)

        if hash_value is None:
            return

        hash_value = int.from_bytes(hash_value)
        self._hash_values[hash_value] = expr

    def reverse_lookup(self, hash_value: int) -> BitVecRef:
        (expr, delta) = self._hash_values[hash_value]
        if expr is not None:
            return expr + delta if delta else expr

        (expr, delta) = precomputed_keccak_registry[hash_value]
        if expr is not None:
            return expr + delta if delta else expr

        return None


class Exec:  # an execution path
    # network
    code: dict[Address, Contract]
    storage: dict[Address, StorageData]  # address -> { storage slot -> value }
    transient_storage: dict[Address, StorageData]  # for TLOAD and TSTORE
    balance: Any  # address -> balance

    # block
    block: Block

    # tx
    context: CallContext
    callback: Callable | None  # to be called when returning back to parent context

    # vm state
    pgm: Contract | None
    pc: int
    insn: Instruction | None
    st: State  # stack and memory
    jumpis: dict[JumpID, dict[bool, int]]  # for loop detection
    addresses_to_delete: set[Address]

    # path
    path: Path  # path conditions
    alias: dict[Address, Address]  # address aliases

    # internal bookkeeping
    cnts: dict[str, int]  # counters
    sha3s: KeccakRegistry  # sha3 hashes generated
    storages: dict[Any, Any]  # storage updates
    balances: dict[Any, Any]  # balance updates
    known_keys: dict[Any, Any]  # maps address to private key
    known_sigs: dict[Any, Any]  # maps (private_key, digest) to (v, r, s)

    # the sequence of calls leading to the state at the start of this execution
    call_sequence: CallSequence

    def __init__(self, **kwargs) -> None:
        self.code = kwargs["code"]
        self.storage = kwargs["storage"]
        self.transient_storage = kwargs["transient_storage"]
        self.balance = kwargs["balance"]
        #
        self.block = kwargs["block"]
        #
        self.context = kwargs["context"]
        self.call_sequence = kwargs.get("call_sequence") or []
        self.callback = kwargs["callback"]
        #
        self.pgm = kwargs["pgm"]
        self.pc = kwargs.get("pc") or 0

        # pgm can have 0 length, which makes it falsey
        self.insn = (
            self.pgm.decode_instruction(self.pc) if self.pgm is not None else None
        )
        self.st = kwargs["st"]
        self.jumpis = kwargs["jumpis"]
        self.addresses_to_delete = kwargs.get("addresses_to_delete") or set()
        #
        self.path = kwargs["path"]
        self.alias = kwargs["alias"]
        #
        self.cnts = kwargs["cnts"]
        self.sha3s = kwargs["sha3s"]
        self.storages = kwargs["storages"]
        self.balances = kwargs["balances"]
        self.known_keys = kwargs.get("known_keys", {})
        self.known_sigs = kwargs.get("known_sigs", {})

        assert_address(self.origin())
        assert_address(self.caller())
        assert_address(self.this())

    def context_str(self) -> str:
        opcode = self.current_opcode()
        return f"addr={hexify(self.this())} pc={self.pc} insn={mnemonic(opcode)}"

    def reset(self):
        """Resets VM state"""

        self.pc = 0
        self.insn = None
        self.st = State()
        self.context.output = CallOutput()
        self.jumpis = {}

    def halt(
        self,
        data: ByteVec | None,
        error: EvmException | None = None,
    ) -> None:
        output = self.context.output
        if output.data is not None:
            raise HalmosException("output already set")

        if data is not None and not isinstance(data, ByteVec):
            raise HalmosException(f"invalid output data {data}")

        output.data = data
        output.error = error
        output.return_scheme = self.current_opcode()

    def is_halted(self) -> bool:
        return self.context.output.data is not None

    def is_panic_of(self, expected_error_codes: set[int]) -> bool:
        return self.context.output.is_panic_of(expected_error_codes)

    def emit_log(self, log: EventLog):
        self.context.trace.append(log)

    def calldata(self) -> ByteVec:
        message = self.message()
        return ByteVec() if message.is_create() else message.data

    def caller(self):
        return self.message().caller

    def origin(self):
        return self.message().origin

    def callvalue(self):
        return self.message().value

    def this(self):
        return self.message().target

    def message(self):
        return self.context.message

    def current_opcode(self) -> Byte:
        return self.insn.opcode

    def fetch_instruction(self) -> None:
        self.insn = self.pgm.decode_instruction(self.pc)

    def resolve_prank(self, to: Address) -> tuple[Address, Address]:
        # this potentially "consumes" the active prank
        prank_result = self.context.prank.lookup(to)
        caller = self.this() if prank_result.sender is None else prank_result.sender
        origin = self.origin() if prank_result.origin is None else prank_result.origin
        return caller, origin

    def set_code(self, who: Address, code: ByteVec | Contract) -> None:
        """
        Sets the code at a given address.
        """
        assert_bv(who)
        assert_address(who)
        self.code[who] = code if isinstance(code, Contract) else Contract(code)

    def __str__(self) -> str:
        return self.dump()

    def dump(self, print_mem=False) -> str:
        output = self.context.output.data
        return hexify(
            "".join(
                [
                    f"PC: {self.this()} {self.pc} {mnemonic(self.current_opcode())}\n",
                    self.st.dump(print_mem=print_mem),
                    f"\nBalance: {self.balance}\n",
                    "Storage:\n",
                    "".join(
                        map(
                            lambda x: f"- {x}: {self.storage[x]}\n",
                            self.storage,
                        )
                    ),
                    "Transient Storage:\n",
                    "".join(
                        map(
                            lambda x: f"- {x}: {self.transient_storage[x]}\n",
                            self.transient_storage,
                        )
                    ),
                    f"Path:\n{self.path}",
                    "Aliases:\n",
                    "".join([f"- {k}: {v}\n" for k, v in self.alias.items()]),
                    f"Output: {output.hex() if isinstance(output, bytes) else output}\n",
                    "Balance updates:\n",
                    "".join(
                        map(
                            lambda x: f"- {x}\n",
                            sorted(self.balances.items(), key=lambda x: str(x[0])),
                        )
                    ),
                    "Storage updates:\n",
                    "".join(
                        map(
                            lambda x: f"- {x}\n",
                            sorted(self.storages.items(), key=lambda x: str(x[0])),
                        )
                    ),
                    "SHA3 hashes:\n",
                    "".join(
                        map(lambda x: f"- {self.sha3s.get_id(x)}: {x}\n", self.sha3s)
                    ),
                ]
            )
        )

    def advance(self, pc: int | None = None) -> None:
        next_pc = pc or self.insn.next_pc
        self.pc = next_pc
        self.insn = self.pgm.decode_instruction(next_pc)

    def quick_custom_check(self, cond: BitVecRef) -> CheckSatResult | None:
        """
        Quick custom checker for specific known patterns.

        This method checks for certain common conditions that can be evaluated
        quickly without invoking the full SMT solver.

        Returns:
            sat if the condition is satisfiable
            unsat if the condition is unsatisfiable
            None if the condition requires full SMT solving
        """

        if is_true(cond):
            return sat

        if is_false(cond):
            return unsat

        # Not(ULE(f_sha3_N(slot), offset + f_sha3_N(slot))), where offset < 2**64
        if match_dynamic_array_overflow_condition(cond):
            return unsat

    def check(self, cond: Any) -> Any:
        cond = simplify(cond)

        # use quick custom checker for common patterns before falling back to SMT solver
        if result := self.quick_custom_check(cond):
            return result

        return self.path.check(cond)

    def select(
        self, array: Any, key: Word, arrays: dict, symbolic: bool = False
    ) -> Word:
        if array in arrays:
            store = arrays[array]
            if store.decl().name() == "store" and store.num_args() == 3:
                base = store.arg(0)
                key0 = store.arg(1)
                val0 = store.arg(2)
                if eq(key, key0):  # structural equality
                    return val0
                if self.check(key == key0) == unsat:  # key != key0
                    return self.select(base, key, arrays, symbolic)
                if self.check(key != key0) == unsat:  # key == key0
                    return val0
        # empty array
        elif not symbolic and re.search(r"^(storage_.+|balance)_00$", str(array)):
            # note: simplifying empty array access might have a negative impact on solver performance
            return ZERO
        return Select(array, key)

    def balance_of(self, addr: Word) -> Word:
        addr = uint160(addr).as_z3()
        value = self.select(self.balance, addr, self.balances)

        # generate emptyness axiom for each array index, instead of using quantified formula
        self.path.append(Select(EMPTY_BALANCE, addr) == ZERO)

        # practical assumption on the max balance per account
        if is_bv_value(value):
            if (v := value.as_long()) > MAX_ETH:
                raise HalmosException(f"balance {v} > MAX_ETH")
        else:
            cond = simplify(ULE(value, con(MAX_ETH)))

            # stop the current path if we know the balance is definitely greater than MAX_ETH
            if is_false(cond):
                raise HalmosException(f"balance {value} > MAX_ETH")

            self.path.append(cond)

        return value

    def balance_update(self, addr: Word, value: Word) -> None:
        if not is_bv(addr):
            addr = uint160(addr).as_z3()

        if not is_bv(value):
            value = uint256(value).as_z3()

        assert addr.size() == 160
        assert value.size() == 256

        new_balance_var = Array(
            f"balance_{uid()}_{1 + len(self.balances):>02}",
            BitVecSort160,
            BitVecSort256,
        )
        new_balance = Store(self.balance, addr, value)
        self.path.append(new_balance_var == new_balance)
        self.balance = new_balance_var
        self.balances[new_balance_var] = new_balance

    def sha3(self) -> None:
        loc: int = self.mloc(check_size=False)
        size: int = self.int_of(self.st.pop(), "symbolic SHA3 data size")
        data = self.st.mslice(loc, size).unwrap() if size else b""
        sha3_image = self.sha3_data(data)
        self.st.push_any(sha3_image)

    def sha3_hash(self, data: Bytes) -> bytes | None:
        """return concrete bytes if the hash can be evaluated, otherwise None"""

        size = byte_length(data)

        if size == 0:
            return EMPTY_KECCAK.to_bytes(32, byteorder="big")

        if isinstance(data, bytes):
            return keccak(data)

        if is_bv_value(data):
            return keccak(bv_value_to_bytes(data))

        if isinstance(data, int):
            # the problem here is that we're not sure about the bit-width of the int
            # this is not supposed to happen, so just log and move on
            debug(f"eval_sha3 received unexpected int value ({data})")

        return None

    def sha3_expr(self, data: Bytes) -> Word:
        """return a symbolic sha3 expression, e.g. f_sha3_256(data)"""

        bitsize = byte_length(data) * 8
        if bitsize == 0:
            return f_sha3_empty

        if isinstance(data, bytes):
            data = bytes_to_bv_value(data)

        fname = f_sha3_name(bitsize)
        f_sha3 = Function(fname, BitVecSorts[bitsize], BitVecSort256)
        return f_sha3(data)

    def sha3_data(self, data: Bytes) -> Word:
        sha3_expr = self.sha3_expr(data)
        sha3_hash = self.sha3_hash(data)
        sha3_hash_bv = bytes_to_bv_value(sha3_hash) if sha3_hash is not None else None

        if sha3_hash is not None:
            # NOTE: skip tracking hashes with large preimages, which are likely creation bytecode,
            # to reduce the overhead in SMT query generation and solving.
            if byte_length(data) > 128:  # 1024 bits
                return sha3_hash_bv

            self.path.append(sha3_expr == sha3_hash_bv)

            # ensure the hash value is within the safe range assumed below
            sha3_hash_int = int.from_bytes(sha3_hash, "big")
            if sha3_hash_int == 0 or sha3_hash_int > 2**256 - 2**64:
                error_msg = f"hash value outside expected range: {sha3_hash.hex()}"
                raise HalmosException(error_msg)

        else:
            # assume hash values are non-zero and sufficiently small to prevent overflow when adding reasonable offsets
            self.path.append(sha3_expr != ZERO)
            self.path.append(ULE(sha3_expr, 2**256 - 2**64))

        # assume no hash collision
        self.assume_sha3_distinct(sha3_expr)

        # associate the original hash expression with the hash value for storage slot decoding later
        self.sha3s.register(sha3_expr, sha3_hash)

        # handle create2 hash
        size = byte_length(data)
        if size == 85:
            first_byte = unbox_int(ByteVec(data).get_byte(0))
            if isinstance(first_byte, int) and first_byte == 0xFF:
                return con(create2_magic_address + self.sha3s.get_id(sha3_expr))

        # return the concrete hash value if available, otherwise return the hash expression
        return sha3_hash_bv if sha3_hash is not None else sha3_expr

    def assume_sha3_distinct(self, sha3_expr: BitVecRef) -> None:
        # skip if already exist
        if sha3_expr in self.sha3s:
            return

        # add a local axiom for hash injectivity
        #
        # an injectivity axiom for f_sha3_[size](data) can be formulated as:
        # - there exists f_inv_sha3 such that: f_inv_sha3(f_sha3_[size](data)) == (data, size)
        #
        # to avoid using a tuple as the return data type, the above can be re-formulated using seperate functions such that:
        # - f_inv_sha3_data(f_sha3_[size](data)) == data
        # - f_inv_sha3_size(f_sha3_[size](data)) == size
        #
        # this approach results in O(n) constraints, where each constraint is independent from other hashes.

        # injectivity is assumed for the lower 160-bit part, which is used for ethereum addresses
        sha3_expr_core = Extract(159, 0, sha3_expr)

        if eq(sha3_expr, f_sha3_empty):
            self.path.append(f_inv_sha3_size(sha3_expr_core) == ZERO)

        else:
            # sha3_expr is expected to be in the format: `sha3_<input_size>(input_data)`
            input_data = sha3_expr.arg(0)
            input_size = input_data.size()

            f_inv_name = f_inv_sha3_name(input_size)
            f_inv_sha3 = Function(f_inv_name, BitVecSort160, BitVecSorts[input_size])
            self.path.append(f_inv_sha3(sha3_expr_core) == input_data)

            self.path.append(f_inv_sha3_size(sha3_expr_core) == con(input_size))

    def new_gas_id(self) -> int:
        self.cnts["gas"] += 1
        return self.cnts["gas"]

    def new_address(self) -> Address:
        self.cnts["address"] += 1
        return con_addr(magic_address + new_address_offset + self.cnts["address"])

    def new_symbol_id(self) -> int:
        self.cnts["symbol"] += 1
        return self.cnts["symbol"]

    def new_call_id(self) -> int:
        self.cnts["call"] += 1
        return self.cnts["call"]

    def returndata(self) -> ByteVec | None:
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
        return len(returndata) if returndata is not None else 0

    def jumpid(self) -> JumpID:
        valid_jumpdests = self.pgm.valid_jumpdests()

        jumpdest_tokens = tuple(
            value for x in self.st.stack if (value := x.value) in valid_jumpdests
        )

        # tuples can be compared efficiently
        return (self.pc, jumpdest_tokens)

    # deploy libraries and resolve library placeholders in hexcode
    def resolve_libs(self, creation_hexcode, deployed_hexcode, lib_references) -> str:
        if lib_references:
            for lib in lib_references:
                address = self.new_address()

                lib_bytecode = Contract.from_hexcode(lib_references[lib]["hexcode"])
                self.set_code(address, lib_bytecode)

                placeholder = lib_references[lib]["placeholder"]
                hex_address = stripped(hex(address.as_long())).zfill(40)

                creation_hexcode = creation_hexcode.replace(placeholder, hex_address)
                deployed_hexcode = deployed_hexcode.replace(placeholder, hex_address)

        return (creation_hexcode, deployed_hexcode)

    def mloc(self, check_size: bool = True) -> int:
        return self.st.mloc(
            self.path.concretization.substitution, check_size=check_size
        )

    def ret(self) -> ByteVec:
        return self.st.ret(self.path.concretization.substitution)

    def int_of(self, x: Any, err: str = None) -> int:
        return int_of(x, err, self.path.concretization.substitution)

    def path_slice(self):
        """
        Identifies and slices constraints related to state variables.

        Collects state variables from balance, code, and storage; then executes path.slice() with them.
        """

        var_set = self.path.get_var_set(self.balance)

        # the keys of self.code are constant
        for _contract in self.code.values():
            _code = _contract._code
            for _chunk in _code.chunks.values():
                if isinstance(_chunk, SymbolicChunk):
                    var_set = itertools.chain(
                        var_set, self.path.get_var_set(_chunk.data)
                    )

        # the keys of self.storage are constant
        for _storage in self.storage.values():
            # the keys of _storage._mapping are constant
            for _val in _storage._mapping.values():
                var_set = itertools.chain(var_set, self.path.get_var_set(_val))

        self.path.slice(var_set)

    def try_resolve_contract_info(
        self, contract: Contract, include_source_map: bool = False
    ) -> tuple[str | None, str | None]:
        """
        Resolves and sets contract information for a newly deployed contract.

        This method attempts to determine the contract name and filename in two ways:
        1. Direct lookup using the contract's bytecode
        2. If that fails and the contract is an ERC-1167 proxy, lookup using the target's bytecode

        Args:
            contract: The Contract object representing the newly deployed contract
        """

        bytecode = contract._code
        contract_name, filename, source_map = BuildOut().get_by_code(bytecode)

        if contract_name is None:
            contract_name, filename, source_map = self._try_resolve_proxy_info(contract)

        if contract_name is None:
            warn(f"unknown deployed bytecode: {hexify(bytecode.unwrap())}")

        contract.contract_name = contract_name
        contract.filename = filename

        if include_source_map:
            contract.source_map = source_map
            contract.process_source_mapping()

        return contract_name, filename

    def _try_resolve_proxy_info(
        self, contract: Contract
    ) -> tuple[str | None, str | None, str | None]:
        """Helper method to resolve contract info for ERC-1167 proxies."""

        target = contract.extract_erc1167_target()
        if target is None:
            return None, None, None

        target_contract = self.code.get(target)
        if target_contract is None:
            return None, None, None

        return BuildOut().get_by_code(target_contract._code)


class Storage:
    pass


class SolidityStorage(Storage):
    @classmethod
    def mk_storagedata(cls) -> StorageData:
        return StorageData()

    @classmethod
    def empty(cls, addr: BitVecRef, slot: int, keys: tuple) -> ArrayRef:
        num_keys = len(keys)
        size_keys = cls.bitsize(keys)
        return Array(
            # note: uuid is excluded to be deterministic
            f"storage_{id_str(addr)}_{slot}_{num_keys}_{size_keys}_00",
            BitVecSorts[size_keys],
            BitVecSort256,
        )

    @classmethod
    def init(
        cls,
        ex: Exec,
        storage: dict,
        addr: Any,
        slot: int,
        keys: tuple,
        num_keys: int,
        size_keys: int,
    ) -> None:
        """
        Initialize storage[addr].mapping[slot][num_keys][size_keys], if not yet initialized
        - case size_keys == 0: scalar type: initialized with zero or symbolic value
        - case size_keys != 0: mapping type: initialized with empty array or symbolic array
        """

        assert_address(addr)
        storage_addr = storage[addr]

        if (slot, num_keys, size_keys) in storage_addr:
            return

        if size_keys > 0:
            # do not use z3 const array `K(BitVecSort(size_keys), ZERO)` when not ex.symbolic
            # instead use normal smt array, and generate emptyness axiom; see load()
            storage_addr[slot, num_keys, size_keys] = cls.empty(addr, slot, keys)
            return

        # size_keys == 0
        storage_addr[slot, num_keys, size_keys] = (
            BitVec(
                # note: uuid is excluded to be deterministic
                f"storage_{id_str(addr)}_{slot}_{num_keys}_{size_keys}_00",
                BitVecSort256,
            )
            if storage_addr.symbolic
            else Z3_ZERO
        )

    @classmethod
    def load(cls, ex: Exec, storage: dict, addr: Any, loc: Word) -> Word:
        (slot, keys, num_keys, size_keys) = cls.get_key_structure(ex, loc)

        cls.init(ex, storage, addr, slot, keys, num_keys, size_keys)

        storage_addr = storage[addr]
        storage_chunk = storage_addr[slot, num_keys, size_keys]

        if num_keys == 0:
            return storage_chunk

        symbolic = storage_addr.symbolic
        concat_keys = concat(keys)

        if not symbolic:
            # generate emptyness axiom for each array index, instead of using quantified formula; see init()
            default_value = Select(cls.empty(addr, slot, keys), concat_keys)
            ex.path.append(default_value == Z3_ZERO)

        return ex.select(storage_chunk, concat_keys, ex.storages, symbolic)

    @classmethod
    def store(cls, ex: Exec, storage: dict, addr: Any, loc: Any, val: Any) -> None:
        (slot, keys, num_keys, size_keys) = cls.get_key_structure(ex, loc)

        cls.init(ex, storage, addr, slot, keys, num_keys, size_keys)

        storage_addr = storage[addr]

        if num_keys == 0:
            storage_addr[slot, num_keys, size_keys] = val
            return

        new_storage_var = Array(
            f"storage_{id_str(addr)}_{slot}_{num_keys}_{size_keys}_{uid()}_{1 + len(ex.storages):>02}",
            BitVecSorts[size_keys],
            BitVecSort256,
        )
        new_storage = Store(storage_addr[slot, num_keys, size_keys], concat(keys), val)
        ex.path.append(new_storage_var == new_storage)

        storage_addr[slot, num_keys, size_keys] = new_storage_var
        ex.storages[new_storage_var] = new_storage

    @classmethod
    def get_key_structure(cls, ex, loc) -> tuple:
        offsets = cls.decode(ex, loc)
        if not len(offsets) > 0:
            raise ValueError(offsets)

        slot, keys = ex.int_of(offsets[0], "symbolic storage base slot"), offsets[1:]

        num_keys = len(keys)
        size_keys = cls.bitsize(keys)

        return (slot, keys, num_keys, size_keys)

    @classmethod
    def decode(cls, ex, loc: Any) -> Any:
        loc = normalize(loc)
        # m[k] : hash(k.m)
        if loc.decl().name() == f_sha3_512_name:
            args = loc.arg(0)
            offset = simplify(Extract(511, 256, args))
            base = simplify(Extract(255, 0, args))
            return cls.decode(ex, base) + (offset, Z3_ZERO)
        # a[i] : hash(a) + i
        elif loc.decl().name() == f_sha3_256_name:
            base = loc.arg(0)
            return cls.decode(ex, base) + (Z3_ZERO,)
        # m[k] : hash(k.m)  where |k| != 256-bit
        elif is_f_sha3_name(loc.decl().name()):
            sha3_input = normalize(loc.arg(0))
            if sha3_input.decl().name() == "concat" and sha3_input.num_args() == 2:
                offset = simplify(sha3_input.arg(0))
                base = simplify(sha3_input.arg(1))
                if offset.size() != 256 and base.size() == 256:
                    return cls.decode(ex, base) + (offset, Z3_ZERO)
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
            args = sorted(
                map(lambda x: cls.decode(ex, x), args),
                key=lambda x: len(x),
                reverse=True,
            )
            if len(args[1]) > 1:
                # only args[0]'s length >= 1, the others must be 1
                raise ValueError(loc)
            return args[0][0:-1] + (
                reduce(lambda r, x: r + x[0], args[1:], args[0][-1]),
            )
        elif is_bv_value(loc):
            orig_term = ex.sha3s.reverse_lookup(loc.as_long())
            if orig_term is not None:
                return cls.decode(ex, orig_term)
            else:
                return (loc,)

        if is_bv(loc):
            return (loc,)
        else:
            raise ValueError(loc)

    @classmethod
    def bitsize(cls, keys: tuple) -> int:
        size = sum([key.size() for key in keys])
        if len(keys) > 0 and size == 0:
            raise ValueError(keys)
        return size


class GenericStorage(Storage):
    @classmethod
    def mk_storagedata(cls) -> StorageData:
        return StorageData()

    @classmethod
    def empty(cls, addr: BitVecRef, loc: BitVecRef) -> ArrayRef:
        return Array(
            # note: uuid is excluded to be deterministic
            f"storage_{id_str(addr)}_{loc.size()}_00",
            BitVecSorts[loc.size()],
            BitVecSort256,
        )

    @classmethod
    def init(
        cls, ex: Exec, storage: dict, addr: Any, loc: BitVecRef, size_keys: int
    ) -> None:
        """
        Initialize storage[addr].mapping[size_keys], if not yet initialized

        NOTE: unlike SolidityStorage, size_keys > 0 in GenericStorage.
              thus it is of mapping type, and initialized with empty array or symbolic array.
        """

        assert_address(addr)
        storage_addr = storage[addr]

        if size_keys not in storage_addr:
            storage_addr[size_keys] = cls.empty(addr, loc)

    @classmethod
    def load(cls, ex: Exec, storage: dict, addr: Any, loc: Word) -> Word:
        loc = cls.decode(ex, loc)
        size_keys = loc.size()

        cls.init(ex, storage, addr, loc, size_keys)

        storage_addr = storage[addr]
        symbolic = storage_addr.symbolic

        if not symbolic:
            # generate emptyness axiom for each array index, instead of using quantified formula; see init()
            default_value = Select(cls.empty(addr, loc), loc)
            ex.path.append(default_value == Z3_ZERO)

        return ex.select(storage_addr[size_keys], loc, ex.storages, symbolic)

    @classmethod
    def store(cls, ex: Exec, storage: dict, addr: Any, loc: Any, val: Any) -> None:
        loc = cls.decode(ex, loc)
        size_keys = loc.size()

        cls.init(ex, storage, addr, loc, size_keys)

        storage_addr = storage[addr]

        new_storage_var = Array(
            f"storage_{id_str(addr)}_{size_keys}_{uid()}_{1 + len(ex.storages):>02}",
            BitVecSorts[size_keys],
            BitVecSort256,
        )
        new_storage = Store(storage_addr[size_keys], loc, val)
        ex.path.append(new_storage_var == new_storage)

        storage_addr[size_keys] = new_storage_var
        ex.storages[new_storage_var] = new_storage

    @classmethod
    def decode(cls, ex, loc: Any) -> Any:
        loc = normalize(loc)
        if loc.decl().name() == f_sha3_512_name:  # hash(hi,lo), recursively
            args = loc.arg(0)
            hi = cls.decode(ex, simplify(Extract(511, 256, args)))
            lo = cls.decode(ex, simplify(Extract(255, 0, args)))
            return cls.simple_hash(Concat(hi, lo))
        elif is_f_sha3_name(loc.decl().name()):
            sha3_input = normalize(loc.arg(0))
            if sha3_input.decl().name() == "concat":
                decoded_sha3_input_args = [
                    cls.decode(ex, sha3_input.arg(i))
                    for i in range(sha3_input.num_args())
                ]
                return cls.simple_hash(concat(decoded_sha3_input_args))
            else:
                return cls.simple_hash(cls.decode(ex, sha3_input))
        elif loc.decl().name() == "bvadd":
            args = loc.children()
            if len(args) < 2:
                raise ValueError(loc)
            return cls.add_all([cls.decode(ex, arg) for arg in args])
        elif is_bv_value(loc):
            orig_term = ex.sha3s.reverse_lookup(loc.as_long())
            if orig_term is not None:
                return cls.decode(ex, orig_term)
            else:
                return loc

        if is_bv(loc):
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
    def add_all(cls, args: list) -> BitVecRef:
        bitsize = max([x.size() for x in args])
        res = con(0, bitsize)
        for x in args:
            if x.size() < bitsize:
                x = simplify(ZeroExt(bitsize - x.size(), x))
            res += x
        return simplify(res)


SomeStorage = TypeVar("SomeStorage", bound=Storage)


def bitwise(op, x: Word, y: Word) -> Word:
    if type(x) is not type(y):
        return bitwise(op, BV(x, size=256), BV(y, size=256))

    # at this point, we expect x and y to be both Bool or both BV
    if op == OP_AND:
        return x.bitwise_and(y)
    elif op == OP_OR:
        return x.bitwise_or(y)
    elif op == OP_XOR:
        return x.bitwise_xor(y)
    else:
        raise ValueError(op, x, y)


class HalmosLogs:
    bounded_loops: list[JumpID]

    def __init__(self) -> None:
        self.bounded_loops = []

    def extend(self, logs: "HalmosLogs") -> None:
        self.bounded_loops.extend(logs.bounded_loops)


@dataclass(slots=True, eq=False, order=False)
class Worklist:
    stack: list[Exec] = field(default_factory=list)

    # for status reporting
    completed_paths: int = 0

    def push(self, ex: Exec):
        self.stack.append(ex)

    def pop(self) -> Exec | None:
        try:
            return self.stack.pop()
        except IndexError:
            return None

    def __len__(self) -> int:
        return len(self.stack)


class SEVM:
    options: HalmosConfig
    fun_info: FunctionInfo
    storage_model: type[SomeStorage]
    logs: HalmosLogs

    def __init__(self, options: HalmosConfig, fun_info: FunctionInfo) -> None:
        self.options = options
        self.fun_info = fun_info
        self.logs = HalmosLogs()

        # init storage model
        is_generic = self.options.storage_layout == "generic"
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

        w1 = normalize(w1)

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
        ex.path.append(ULE(term, x))  # (x / y) <= x
        return term

    def mk_mod(self, ex: Exec, x: Any, y: Any) -> Any:
        term = f_mod[x.size()](x, y)
        ex.path.append(ULE(term, y))  # (x % y) <= y
        # ex.path.append(Or(y == ZERO, ULT(term, y))) # (x % y) < y if y != 0
        return term

    def arith(self, ex: Exec, op: int, w1: Word, w2: Word) -> Word:
        if op == OP_ADD:
            return w1.add(w2)

        if op == OP_SUB:
            return w1.sub(w2)

        if op == OP_MUL:
            return w1.mul(w2, abstraction=f_mul[w1.size])

        if op == OP_DIV:
            # TODO: div_xy_y

            term = w1.div(w2, abstraction=f_div)
            if term.is_symbolic:
                ex.path.append(ULE(term.as_z3(), w1.as_z3()))  # (x / y) <= x
            return term

        if op == OP_MOD:
            term = w1.mod(w2, abstraction=f_mod[w1.size])
            if term.is_symbolic:
                # (x % y) <= y
                # not ULT, because y could be 0 and x % 0 = 0
                ex.path.append(ULE(term.as_z3(), w2.as_z3()))
            return term

        if op == OP_SDIV:
            return w1.sdiv(w2, abstraction=f_sdiv)

        if op == OP_SMOD:
            return w1.smod(w2, abstraction=f_smod)

        if op == OP_EXP:
            return w1.exp(
                w2,
                exp_abstraction=f_exp,
                mul_abstraction=f_mul[w1.size],
                smt_exp_by_const=self.options.smt_exp_by_const,
            )

        raise ValueError(op)

    def mk_storagedata(self) -> StorageData:
        return self.storage_model.mk_storagedata()

    def fresh_transient_storage(self, ex: Exec) -> dict:
        return {addr: self.mk_storagedata() for addr in ex.transient_storage}

    def sload(self, ex: Exec, addr: Address, loc: BV, transient: bool = False) -> Word:
        loc = loc.as_z3()

        storage = ex.transient_storage if transient else ex.storage

        val = self.storage_model.load(ex, storage, addr, loc)

        ex.context.trace.append(StorageRead(addr, loc, val, transient))
        return val

    def sstore(
        self, ex: Exec, addr: Address, loc: BV, val: BV, transient: bool = False
    ) -> None:
        loc = loc.as_z3()
        val = val.as_z3()

        storage = ex.transient_storage if transient else ex.storage

        ex.context.trace.append(StorageWrite(addr, loc, val, transient))

        if ex.message().is_static:
            raise WriteInStaticContext(ex.context_str())

        if is_bool(val):
            val = If(val, Z3_ONE, Z3_ZERO)

        self.storage_model.store(ex, storage, addr, loc, val)

    def resolve_address_alias(
        self, ex: Exec, target: Address, stack, allow_branching=True
    ) -> Address:
        # TODO: avoid the extra wrapping/unwrapping
        if type(target) is BV:
            target = target.as_z3()

        assert_bv(target)
        assert target.size() == 160

        if target in ex.code:
            return target

        debug_once(
            f"Address {hexify(target)} not in: [{', '.join([hexify(addr) for addr in ex.code])}]"
        )

        if is_bv_value(target):
            debug_once(f"Empty address: {hexify(target)}")
            return None

        if target in ex.alias:
            return ex.alias[target]  # may return None

        potential_aliases = []
        for addr in ex.code:
            # exclude the test contract from alias candidates
            if eq(addr, FOUNDRY_TEST):
                continue
            alias_cond = target == addr
            if ex.check(alias_cond) != unsat:
                debug_once(
                    f"Potential address alias: {hexify(addr)} for {hexify(target)}"
                )
                potential_aliases.append((addr, alias_cond))

        emptyness_cond = And([target != addr for addr in ex.code])
        if ex.check(emptyness_cond) != unsat:
            debug_once(f"Potential empty address: {hexify(target)}")
            potential_aliases.append((None, emptyness_cond))

        if not potential_aliases:
            raise InfeasiblePath("resolve_address_alias: no potential aliases")

        head, *tail = potential_aliases

        if not allow_branching and tail:
            raise HalmosException(f"multiple aliases exist: {hexify(target)}")

        for addr, cond in tail:
            new_ex = self.create_branch(ex, cond, ex.pc)
            new_ex.alias[target] = addr
            stack.push(new_ex)

        addr, cond = head
        ex.path.append(cond, branching=True)
        ex.alias[target] = addr
        return addr

    def handle_insufficient_fund_case(
        self, caller: Address, value: BV, message: Message, ex: Exec, stack: Worklist
    ):
        if value == ZERO:
            return

        insufficiency_cond = simplify(ULT(ex.balance_of(caller), value.as_z3()))

        # note: although creating a new branch is unnecessary when insufficiency_cond is true,
        # such definite insufficiency is rare, and this logic is simpler to maintain.
        # the definite insufficiency is handled later by transfer_value().
        if ex.check(insufficiency_cond) != unsat:
            fail_ex = self.create_branch(ex, insufficiency_cond, ex.pc)
            fail_ex.context.trace.append(
                CallContext(
                    message=message,
                    output=CallOutput(data=ByteVec(), error=InsufficientFunds()),
                    depth=ex.context.depth + 1,
                )
            )
            fail_ex.st.push(ZERO)
            fail_ex.advance()
            stack.push(fail_ex)

    def transfer_value(
        self,
        ex: Exec,
        caller: Address,
        to: Address,
        value: Word,
        condition: BoolRef | None = None,
    ) -> None:
        # no-op if value is zero
        if value.is_concrete and value.value == 0:
            return

        caller_balance: BitVecRef = ex.balance_of(caller)

        # assume balance is enough; otherwise ignore this path
        # note: evm requires enough balance even for self-transfer
        balance_cond = simplify(UGE(caller_balance, value.as_z3()))
        if is_false(balance_cond):
            raise InfeasiblePath("transfer_value: balance is not enough")

        ex.path.append(balance_cond)

        # conditional transfer
        if condition is not None:
            value = If(condition, value, Z3_ZERO)

        ex.balance_update(caller, BV(caller_balance).sub(value))
        # NOTE: ex.balance_of(to) must be called **after** updating the caller's balance above, to correctly handle the self-transfer case
        ex.balance_update(to, BV(ex.balance_of(to)).add(value))

    def call(
        self,
        ex: Exec,
        op: int,
        to_alias: Address,
        stack: Worklist,
    ) -> None:
        # `to`: the original (symbolic) target address
        # `to_alias`: a (concrete) alias of the target considered in this path.
        #            it could be None, indicating a non-existent address.
        ex.st.pop()  # gas

        to: BV = uint160(ex.st.pop())
        fund: BV = ZERO if op in [OP_STATICCALL, OP_DELEGATECALL] else ex.st.popi()

        arg_loc: int = ex.mloc(check_size=False)
        arg_size: int = ex.int_of(ex.st.pop(), "symbolic CALL input data size")

        ret_loc: int = ex.mloc(check_size=False)
        ret_size: int = ex.int_of(ex.st.pop(), "symbolic CALL return data size")

        if not arg_size >= 0:
            raise ValueError(arg_size)

        if not ret_size >= 0:
            raise ValueError(ret_size)

        pranked_caller, pranked_origin = ex.resolve_prank(to)
        arg = ex.st.mslice(arg_loc, arg_size)

        resolved_to = to_alias if to_alias is not None else to
        message = Message(
            target=resolved_to if op in [OP_CALL, OP_STATICCALL] else ex.this(),
            caller=pranked_caller if op != OP_DELEGATECALL else ex.caller(),
            origin=pranked_origin,
            value=fund if op != OP_DELEGATECALL else ex.callvalue(),
            data=arg,
            is_static=(ex.context.message.is_static or op == OP_STATICCALL),
            call_scheme=op,
        )

        self.handle_insufficient_fund_case(pranked_caller, fund, message, ex, stack)

        def send_callvalue(condition: BoolRef | None = None) -> None:
            # no balance update for CALLCODE which transfers to itself
            if op == OP_CALL:
                # TODO: revert if context is static
                # NOTE: we cannot use `to_alias` here because it could be None
                self.transfer_value(ex, pranked_caller, to, fund, condition)

        def call_known(to: Address) -> None:
            # backup current state
            orig_code = ex.code.copy()
            orig_storage = deepcopy(ex.storage)
            orig_transient_storage = deepcopy(ex.transient_storage)
            orig_balance = ex.balance

            # transfer msg.value
            send_callvalue()

            def callback(new_ex: Exec, stack):
                # continue execution in the context of the parent
                # pessimistic copy because the subcall results may diverge
                subcall = new_ex.context

                # restore context
                new_ex.context = deepcopy(ex.context)
                new_ex.context.trace.append(subcall)
                new_ex.callback = ex.callback

                if subcall.is_stuck():
                    # internal errors abort the current path,
                    # so we don't need to add it to the worklist
                    stack.completed_paths += 1
                    yield new_ex
                    return

                # restore vm state
                new_ex.pgm = ex.pgm
                new_ex.pc = ex.pc
                new_ex.insn = ex.insn
                new_ex.st = deepcopy(ex.st)
                new_ex.jumpis = deepcopy(ex.jumpis)

                returndata = subcall.output.data
                copy_returndata_to_memory(returndata, ret_loc, ret_size, new_ex)

                # set status code on the stack
                subcall_success = subcall.output.error is None
                new_ex.st.push(ONE if subcall_success else ZERO)

                if not subcall_success:
                    # revert network states
                    new_ex.code = orig_code.copy()
                    new_ex.storage = deepcopy(orig_storage)
                    new_ex.transient_storage = deepcopy(orig_transient_storage)
                    new_ex.balance = orig_balance

                # add to worklist even if it reverted during the external call
                new_ex.advance()
                stack.push(new_ex)

            sub_ex = Exec(
                code=ex.code,
                storage=ex.storage,
                transient_storage=ex.transient_storage,
                balance=ex.balance,
                #
                block=ex.block,
                #
                context=CallContext(message=message, depth=ex.context.depth + 1),
                call_sequence=ex.call_sequence,
                callback=callback,
                #
                pgm=ex.code[to],
                pc=0,
                st=State(),
                jumpis={},
                #
                path=ex.path,
                alias=ex.alias,
                #
                cnts=ex.cnts,
                sha3s=ex.sha3s,
                storages=ex.storages,
                balances=ex.balances,
                known_keys=ex.known_keys,
                known_sigs=ex.known_sigs,
            )

            stack.push(sub_ex)

        def call_unknown() -> None:
            # ecrecover
            if to == ECRECOVER_PRECOMPILE:
                # TODO: explicitly return empty data in case of an error
                # TODO: validate input and fork on error?
                # - v in [27, 28]
                # - r, s in [1, secp256k1n)

                # call never fails, errors result in empty returndata
                exit_code = ONE

                # wrapping guarantees that the arguments are bitvecs
                digest = uint256(arg.get_word(0)).as_z3()
                v = uint8(arg.get_word(32)).as_z3()
                r = uint256(arg.get_word(64)).as_z3()
                s = uint256(arg.get_word(96)).as_z3()

                # TODO: empty returndata in error
                ret = ByteVec(uint256(f_ecrecover(digest, v, r, s)))

            elif to == SHA256_PRECOMPILE:
                exit_code = ONE
                f_sha256 = Function(
                    f"f_sha256_{arg_size}", BitVecSorts[arg_size], BitVecSort256
                )

                unwrapped = arg.unwrap()
                wrapped = (
                    unwrapped if is_bv(unwrapped) else bytes_to_bv_value(unwrapped)
                )
                ret = ByteVec(f_sha256(wrapped))

            elif to == RIPEMD160_PRECOMPILE:
                exit_code = ONE
                f_ripemd160 = Function(
                    f"f_ripemd160_{arg_size}", BitVecSorts[arg_size], BitVecSort160
                )

                unwrapped = arg.unwrap()
                wrapped = (
                    unwrapped if is_bv(unwrapped) else bytes_to_bv_value(unwrapped)
                )
                ret = ByteVec(uint256(f_ripemd160(wrapped)))

            elif to == IDENTITY_PRECOMPILE:
                exit_code = ONE
                ret = arg

            elif to == MODEXP_PRECOMPILE:
                exit_code = ONE
                modulus_size = ex.int_of(arg.get_word(64))
                f_modexp = Function(
                    f"f_modexp_{arg_size}_{modulus_size}",
                    BitVecSorts[arg_size],
                    BitVecSorts[modulus_size],
                )

                unwrapped = arg.unwrap()
                wrapped = (
                    unwrapped if is_bv(unwrapped) else bytes_to_bv_value(unwrapped)
                )
                ret = ByteVec(f_modexp(wrapped))

            elif to == ECADD_PRECOMPILE:
                exit_code = ONE
                f_ecadd = Function("f_ecadd", BitVecSorts[1024], BitVecSorts[512])

                unwrapped = arg.unwrap()
                wrapped = (
                    unwrapped if is_bv(unwrapped) else bytes_to_bv_value(unwrapped)
                )
                ret = ByteVec(f_ecadd(wrapped))

            elif to == ECMUL_PRECOMPILE:
                exit_code = ONE
                f_ecmul = Function("f_ecmul", BitVecSorts[768], BitVecSorts[512])

                unwrapped = arg.unwrap()
                wrapped = (
                    unwrapped if is_bv(unwrapped) else bytes_to_bv_value(unwrapped)
                )
                ret = ByteVec(f_ecmul(wrapped))

            # ecpairing
            elif to == ECPAIRING_PRECOMPILE:
                exit_code = ONE
                f_ecpairing = Function("f_ecpairing", BitVecSorts[1536], BitVecSorts[1])

                unwrapped = arg.unwrap()
                wrapped = (
                    unwrapped if is_bv(unwrapped) else bytes_to_bv_value(unwrapped)
                )
                ret = ByteVec(uint256(f_ecpairing(wrapped)))

            # blake2f
            elif to == BLAKE2F_PRECOMPILE:
                exit_code = ONE
                f_blake2f = Function("f_blake2f", BitVecSorts[1704], BitVecSorts[512])

                unwrapped = arg.unwrap()
                wrapped = (
                    unwrapped if is_bv(unwrapped) else bytes_to_bv_value(unwrapped)
                )
                ret = ByteVec(f_blake2f(wrapped))

            elif to == POINT_EVALUATION_PRECOMPILE:
                exit_code = ONE
                f_point_evaluation = Function(
                    "f_point_evaluation", BitVecSorts[1544], BitVecSorts[512]
                )

                unwrapped = arg.unwrap()
                wrapped = (
                    unwrapped if is_bv(unwrapped) else bytes_to_bv_value(unwrapped)
                )
                ret = ByteVec(f_point_evaluation(wrapped))

            # halmos cheat code
            elif to == halmos_cheat_code.address:
                exit_code = ONE
                ret = halmos_cheat_code.handle(self, ex, arg, stack)

            # vm cheat code
            elif to == hevm_cheat_code.address:
                exit_code = ONE
                ret = hevm_cheat_code.handle(self, ex, arg, stack)

            # console
            elif to == console.address:
                exit_code = ONE
                console.handle(ex, arg)
                ret = ByteVec()

            # non-existing contracts
            else:
                # in evm, calls to non-existing contracts always succeed with empty returndata
                # TODO: exitcode should be 0 when balance is not enough for callvalue
                exit_code = ONE
                ret = ByteVec()

            # push exit code
            if exit_code.is_concrete:
                ex.st.push(exit_code)

                # transfer msg.value
                if exit_code.value != 0:
                    send_callvalue()
            else:
                exit_code_var = BitVec(
                    f"call_exit_code_{uid()}_{ex.new_call_id():>02}", BitVecSort256
                )
                ex.path.append(exit_code_var == exit_code)
                ex.st.push_any(exit_code_var)

                # transfer msg.value
                send_callvalue(exit_code_var != ZERO)

            ret_lst = ret if isinstance(ret, list) else [ret]

            last_idx = len(ret_lst) - 1
            for idx, ret_ in enumerate(ret_lst):
                if not isinstance(ret_, ByteVec):
                    raise HalmosException(f"Invalid return value: {ret_}")

                new_ex = (
                    self.create_branch(ex, BoolVal(True), ex.pc)
                    if idx < last_idx
                    else ex
                )
                copy_returndata_to_memory(ret_, ret_loc, ret_size, new_ex)
                new_ex.context.trace.append(
                    CallContext(
                        message=message,
                        output=CallOutput(data=ret_),
                        depth=new_ex.context.depth + 1,
                    )
                )

                new_ex.advance()
                stack.push(new_ex)

        # precompiles or cheatcodes
        if (
            # precompile
            (to.is_concrete and int(to) in range(1, 11))
            # cheatcode calls
            or to in CHEATCODE_ADDRESSES
            # non-existing contract call
            or to_alias is None
        ):
            call_unknown()
            return

        call_known(to_alias)

    def create(
        self,
        ex: Exec,
        op: int,
        stack: Worklist,
    ) -> None:
        if ex.message().is_static:
            raise WriteInStaticContext(ex.context_str())

        value: BV = ex.st.popi()
        loc: int = ex.int_of(ex.st.pop(), "symbolic CREATE offset")
        size: int = ex.int_of(ex.st.pop(), "symbolic CREATE size")

        if op == OP_CREATE2:
            salt = ex.st.pop()

        # check if there is an active prank
        pranked_caller, pranked_origin = ex.resolve_prank(con_addr(0))

        # contract creation code
        create_hexcode = ex.st.mslice(loc, size)
        create_code = Contract(create_hexcode)

        # new account address
        if op == OP_CREATE:
            new_addr = ex.new_address()
        elif op == OP_CREATE2:  # OP_CREATE2
            # create_hexcode must be z3 expression to be passed into sha3_data
            create_hexcode = create_hexcode.unwrap()

            if is_bv(create_hexcode):
                create_hexcode = simplify(create_hexcode)
            else:
                create_hexcode = bytes_to_bv_value(create_hexcode)

            code_hash = ex.sha3_data(create_hexcode)
            hash_data = simplify(
                Concat(
                    con(0xFF, 8),
                    uint160(pranked_caller).as_z3(),
                    salt.as_z3(),
                    code_hash,
                )
            )
            new_addr = uint160(ex.sha3_data(hash_data)).as_z3()
        else:
            raise HalmosException(f"Unknown CREATE opcode: {op}")

        message = Message(
            target=new_addr,
            caller=pranked_caller,
            origin=pranked_origin,
            value=value,
            data=create_hexcode,
            is_static=False,
            call_scheme=op,
        )

        self.handle_insufficient_fund_case(pranked_caller, value, message, ex, stack)

        if new_addr in ex.code:
            # address conflicts don't revert, they push 0 on the stack and continue
            ex.st.push(ZERO)
            ex.advance()

            # add a virtual subcontext to the trace for debugging purposes
            subcall = CallContext(message=message, depth=ex.context.depth + 1)
            subcall.output.data = ByteVec()
            subcall.output.error = AddressCollision()
            ex.context.trace.append(subcall)

            stack.push(ex)
            return

        for addr in ex.code:
            ex.path.append(new_addr != addr)  # ensure new address is fresh

        # backup current state
        orig_code = ex.code.copy()
        orig_storage = deepcopy(ex.storage)
        orig_transient_storage = deepcopy(ex.transient_storage)
        orig_balance = ex.balance

        # setup new account
        ex.set_code(new_addr, Contract(b""))  # existing code must be empty

        # existing storage may not be empty and reset here
        ex.storage[new_addr] = self.mk_storagedata()
        ex.transient_storage[new_addr] = self.mk_storagedata()

        # transfer value
        self.transfer_value(ex, pranked_caller, new_addr, value)

        def callback(new_ex: Exec, stack):
            subcall = new_ex.context

            # continue execution in the context of the parent
            # pessimistic copy because the subcall results may diverge
            new_ex.context = deepcopy(ex.context)
            new_ex.context.trace.append(subcall)
            new_ex.callback = ex.callback

            # restore vm state
            new_ex.pgm = ex.pgm
            new_ex.pc = ex.pc
            new_ex.insn = ex.insn
            new_ex.st = deepcopy(ex.st)
            new_ex.jumpis = deepcopy(ex.jumpis)

            if subcall.is_stuck():
                # internal errors abort the current path,
                stack.completed_paths += 1
                yield new_ex
                return

            elif subcall.output.error is None:
                deployed_bytecode = subcall.output.data

                # new contract code, will revert if data is None
                new_code = Contract(deployed_bytecode)
                new_ex.try_resolve_contract_info(new_code, self.options.coverage_output)

                new_ex.set_code(new_addr, new_code)

                # push new address to stack
                new_ex.st.push_any(new_addr)

            else:
                # creation failed
                new_ex.st.push(ZERO)

                # revert network states
                new_ex.code = orig_code.copy()
                new_ex.storage = deepcopy(orig_storage)
                new_ex.transient_storage = deepcopy(orig_transient_storage)
                new_ex.balance = orig_balance

            # add to worklist
            new_ex.advance()
            stack.push(new_ex)

        sub_ex = Exec(
            code=ex.code,
            storage=ex.storage,
            transient_storage=ex.transient_storage,
            balance=ex.balance,
            #
            block=ex.block,
            #
            context=CallContext(message=message, depth=ex.context.depth + 1),
            call_sequence=ex.call_sequence,
            callback=callback,
            #
            pgm=create_code,
            pc=0,
            st=State(),
            jumpis={},
            #
            path=ex.path,
            alias=ex.alias,
            #
            cnts=ex.cnts,
            sha3s=ex.sha3s,
            storages=ex.storages,
            balances=ex.balances,
            known_keys=ex.known_keys,
            known_sigs=ex.known_sigs,
        )

        stack.push(sub_ex)

    def jumpi(
        self,
        ex: Exec,
        stack: Worklist,
        target: int,
        cond: Bool,
    ) -> None:
        cond_z3 = cond.as_z3()
        cond_true = simplify(cond_z3)
        cond_false = simplify(Not(cond_true))

        check_true = ex.check(cond_true)
        check_false = ex.check(cond_false)

        potential_true: bool = check_true != unsat
        potential_false: bool = check_false != unsat

        must_true: bool = check_true == sat and check_false == unsat
        must_false: bool = check_true == unsat and check_false == sat

        is_symbolic_cond = not (must_true or must_false)

        # note: both may be false if the previous path condition was considered unknown but turns out to be unsat later

        # we don't apply the loop unrolling limit to constant loops, where the branching condition is definitely true or false.
        # note that potential_* values alone are not enough, because unsat may result from earlier infeasible path conditions that haven't been pruned due to smt timeout.

        follow_true = False
        follow_false = False

        jid = ex.jumpid()
        visited = ex.jumpis.get(jid, {True: 0, False: 0})

        if is_symbolic_cond:
            # for loop unrolling
            follow_true = potential_true and visited[True] < self.options.loop
            follow_false = potential_false and visited[False] < self.options.loop

            unroll_limit_reached_true = potential_true and not follow_true
            unroll_limit_reached_false = potential_false and not follow_false

            if unroll_limit_reached_true or unroll_limit_reached_false:
                self.logs.bounded_loops.append(jid)

                # rendering ex.path to string can be expensive, so only do it if debug is enabled
                if self.options.debug:
                    debug(
                        f"\nloop id: {jid}\n"
                        f"loop condition: {cond}\n"
                        f"calldata: {ex.calldata()}\n"
                        f"path condition:\n{ex.path}\n"
                    )
        else:
            # for constant-bounded loops
            follow_true = potential_true
            follow_false = potential_false

        new_ex_true = None
        new_ex_false = None

        if follow_true:
            if target not in ex.pgm.valid_jumpdests():
                raise InvalidJumpDestError(f"Invalid jump destination: 0x{target:X}")

            if follow_false:
                new_ex_true = self.create_branch(ex, cond_true, target)
            else:
                new_ex_true = ex
                new_ex_true.path.append(cond_true, branching=True)
                new_ex_true.advance(pc=target + 1)

        if follow_false:
            new_ex_false = ex
            new_ex_false.path.append(cond_false, branching=True)
            new_ex_false.advance()

        if new_ex_true:
            if is_symbolic_cond:
                new_ex_true.jumpis[jid] = {
                    True: visited[True] + 1,
                    False: visited[False],
                }
            stack.push(new_ex_true)

        if new_ex_false:
            if is_symbolic_cond:
                new_ex_false.jumpis[jid] = {
                    True: visited[True],
                    False: visited[False] + 1,
                }
            stack.push(new_ex_false)

    def create_branch(self, ex: Exec, cond: BitVecRef, target: int) -> Exec:
        new_path = ex.path.branch(cond)
        new_ex = Exec(
            code=ex.code.copy(),  # shallow copy for potential new contract creation; existing code doesn't change
            storage=deepcopy(ex.storage),
            transient_storage=deepcopy(ex.transient_storage),
            balance=ex.balance,
            #
            block=deepcopy(ex.block),
            #
            context=deepcopy(ex.context),
            callback=ex.callback,
            #
            pgm=ex.pgm,
            pc=target,
            st=deepcopy(ex.st),
            jumpis=deepcopy(ex.jumpis),
            #
            path=new_path,
            alias=ex.alias.copy(),
            #
            cnts=deepcopy(ex.cnts),
            sha3s=ex.sha3s.copy(),
            storages=ex.storages.copy(),
            balances=ex.balances.copy(),
            known_keys=ex.known_keys,  # pass by reference, not need to copy
            known_sigs=ex.known_sigs,  # pass by reference, not need to copy
            #
            call_sequence=ex.call_sequence,  # pass by reference
        )
        return new_ex

    def calldataload(
        self,
        ex: Exec,
        stack: Worklist,
    ) -> None:
        """
        Handle generalized calldata encoding. (See calldata.encode for more details on generalized encoding.)

        If the loaded value is a symbol, it may represent a size symbol for dynamic parameters, and can be resolved as follows:
        - If the symbol is already constrained to a concrete value in the current path condition, it is replaced by that value.
        - If the symbol is associated with candidate values, the current path is branched over these candidates.
        """

        offset: int = ex.int_of(ex.st.pop(), "symbolic CALLDATALOAD offset")

        loaded = ex.calldata().get_word(offset)

        if is_expr_var(loaded):
            concrete_loaded = ex.path.concretization.substitution.get(loaded)

            if concrete_loaded is not None:  # could be zero
                loaded = concrete_loaded

            elif loaded in ex.path.concretization.candidates:
                debug_once(
                    f"Concretize: {loaded} over {ex.path.concretization.candidates[loaded]}"
                )

                for candidate in ex.path.concretization.candidates[loaded]:
                    new_ex = self.create_branch(ex, loaded == candidate, ex.pc)
                    new_ex.st.push_any(candidate)
                    new_ex.advance()
                    stack.push(new_ex)
                return
        ex.st.push_any(loaded)
        ex.advance()
        stack.push(ex)

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

    def run_message(self, pre_ex: Exec, message: Message, path: Path) -> Iterator[Exec]:
        """
        Executes the given transaction from the given input state.

        Note: As this involves executing a new transaction, the transient storage is reset to empty instead of being inherited from the input state.
        """
        ex0 = Exec(
            code=pre_ex.code.copy(),  # shallow copy
            storage=deepcopy(pre_ex.storage),
            transient_storage=self.fresh_transient_storage(pre_ex),  # empty
            balance=pre_ex.balance,
            #
            block=deepcopy(pre_ex.block),
            #
            context=CallContext(message=message),
            call_sequence=pre_ex.call_sequence,  # pass by reference
            callback=None,
            #
            pgm=pre_ex.code[message.target],
            pc=0,
            st=State(),
            jumpis={},
            #
            path=path,
            alias=pre_ex.alias.copy(),
            #
            cnts=deepcopy(pre_ex.cnts),
            sha3s=pre_ex.sha3s.copy(),
            storages=pre_ex.storages.copy(),
            balances=pre_ex.balances.copy(),
        )
        yield from self.run(ex0)

    def run(self, ex0: Exec) -> Iterator[Exec]:
        next_ex: Exec | None = ex0
        stack: Worklist = Worklist()

        def finalize(ex: Exec):
            # if it's at the top-level, there is no callback; yield the current execution state
            if ex.callback is None:
                stack.completed_paths += 1
                yield ex

            # otherwise, execute the callback to return to the parent execution context
            # note: `yield from` is used as the callback may yield the current execution state that got stuck
            else:
                yield from ex.callback(ex, stack)

        # cache config options out of the hot loop
        no_status = self.options.no_status
        max_depth = self.options.depth
        print_steps = self.options.print_steps
        print_mem = self.options.print_mem
        profile_instructions = self.options.profile_instructions
        profiler = Profiler()
        coverage_output = self.options.coverage_output
        coverage = CoverageReporter()
        start_time = timer()
        fun_name = self.fun_info.name

        # TODO: break the backward dependency from traces, and use the existing trace lender methods
        call_seq_str = "\n".join(
            f"{hexify(call.message.target)}::{hexify(call.message.data[:4].unwrap())}"
            for call in ex0.call_sequence
        )

        step_id = 0
        step_interval_mask = PULSE_INTERVAL - 1

        # make sure the initial instruction has been fetched
        if not ex0.insn:
            ex0.fetch_instruction()

        # not strictly necessary, but helps type checking
        ex: Exec | None = None

        while (ex := next_ex or stack.pop()) is not None:
            try:
                next_ex = None
                step_id += 1

                # display progress
                if not no_status and step_id & step_interval_mask == 0:
                    elapsed = timer() - start_time
                    speed = step_id / elapsed

                    # hh:mm:ss
                    elapsed_fmt = timedelta(seconds=int(elapsed))

                    ui.update_status(
                        f"{fun_name}: "
                        f"[{elapsed_fmt}] {speed:.0f} ops/s"
                        f" | completed paths: {stack.completed_paths}"
                        f" | outstanding paths: {len(stack)}"
                        f"\n{call_seq_str}"
                    )

                if not ex.path.is_activated():
                    ex.path.activate()

                # PathEndingException may not be immediately raised; it could be delayed until it comes out of the worklist
                # see the assert cheatcode hanlder logic for the delayed case
                if isinstance(ex.context.output.error, PathEndingException):
                    raise ex.context.output.error

                if ex.context.depth > MAX_CALL_DEPTH:
                    raise MessageDepthLimitError(ex.context)

                insn: Instruction = ex.insn
                opcode: int = insn.opcode
                state: State = ex.st

                if coverage_output:
                    # Record instruction coverage
                    coverage.record_instruction(insn)

                if profile_instructions:
                    extra = ""
                    if opcode == OP_ISZERO:
                        extra = "Bool" if "Bool" in type(state.top()).__name__ else "BV"
                    profiler.increment(opcode, extra)

                if max_depth and step_id > max_depth:
                    warn(
                        f"{self.fun_info.sig}: incomplete execution due to the specified limit: --depth {max_depth}",
                        allow_duplicate=False,
                    )
                    continue

                if print_steps:
                    print(ex.dump(print_mem=print_mem))

                # Reordered based on frequency data
                if OP_PUSH1 <= opcode <= OP_PUSH31:
                    state.push(insn.operand)

                elif opcode == OP_PUSH32:
                    val = insn.operand
                    assert val.size == 256

                    # Special handling for PUSH32 with concrete values
                    if val.is_concrete:
                        # TODO: support more commonly used concrete keccak values
                        if val.value == EMPTY_KECCAK:
                            state.push_any(ex.sha3_data(b""))
                        else:
                            state.push(val)
                    else:
                        # Symbolic value
                        state.push(val)

                elif opcode == OP_POP:
                    state.pop()

                elif opcode == OP_JUMPDEST:
                    pass

                elif opcode == OP_ADD:
                    w1 = state.popi()
                    state.set_top(w1.add(state.topi()))

                elif OP_DUP1 <= opcode <= OP_DUP16:
                    state.dup(opcode - OP_DUP1 + 1)

                elif OP_SWAP1 <= opcode <= OP_SWAP16:
                    state.swap(opcode - OP_SWAP1 + 1)

                elif opcode == OP_JUMP:
                    # no need to explicitly convert to BV
                    dst = state.pop()

                    # if dst is concrete, just jump
                    if dst.is_concrete:
                        # target can be an int or bool here, the membership check works for both
                        target = dst.value
                        if target not in ex.pgm.valid_jumpdests():
                            raise InvalidJumpDestError(target)

                        # we just validated that this is indeed a JUMPDEST so we can safely skip it
                        ex.advance(pc=target + 1)
                        next_ex = ex

                    # otherwise, create a new execution for feasible targets
                    elif self.options.symbolic_jump:
                        reachable_targets = [
                            target
                            for target in ex.pgm.valid_jumpdests()
                            if ex.check(dst.as_z3() == target) != unsat
                        ]

                        if not reachable_targets:
                            raise InvalidJumpDestError(dst)

                        for target in reachable_targets:
                            cond = dst.as_z3() == target
                            new_ex = self.create_branch(ex, cond, target)
                            stack.push(new_ex)
                    else:
                        raise NotConcreteError(f"symbolic JUMP target: {dst}")

                    continue

                elif opcode == OP_JUMPI:
                    target: int = ex.int_of(ex.st.pop(), "symbolic JUMPI target")

                    cond_val = ex.st.pop()
                    cond = Bool(cond_val) if type(cond_val) is BV else cond_val

                    if cond.is_true:
                        if target not in ex.pgm.valid_jumpdests():
                            raise InvalidJumpDestError(target)

                        # we just validated that this is indeed a JUMPDEST so we can safely skip it
                        ex.advance(pc=target + 1)
                        next_ex = ex
                        continue

                    if cond.is_false:
                        ex.advance(pc=insn.next_pc)
                        next_ex = ex
                        continue

                    # handle symbolic conditions
                    self.jumpi(ex, stack, target, cond)
                    continue

                elif opcode == OP_ISZERO:
                    state.set_top(state.top().is_zero())

                elif opcode == OP_MSTORE:
                    loc: int = ex.mloc(check_size=True)
                    val: BV = state.popi()
                    state.memory.set_word(loc, val)

                elif opcode == OP_MLOAD:
                    loc: int = ex.mloc(check_size=True)
                    state.push_any(state.memory.get_word(loc))

                elif opcode == OP_PUSH0:
                    state.push(ZERO)

                elif opcode == OP_SUB:
                    w1 = state.popi()
                    state.set_top(w1.sub(state.topi()))

                elif opcode == OP_SHL:
                    w1 = state.popi()
                    state.set_top(state.topi().lshl(w1))

                elif opcode == OP_AND:
                    w1 = state.pop()
                    state.set_top(bitwise(OP_AND, w1, state.top()))

                # Rest of the less frequent opcodes

                elif opcode == OP_SHR:
                    w1 = state.popi()
                    state.set_top(state.topi().lshr(w1))

                elif opcode == OP_GT:
                    w1: BV = state.popi()
                    state.set_top(w1.ugt(state.topi()))  # bvugt

                elif opcode == OP_EQ:
                    w1: BV = state.pop()
                    w2: BV = state.pop()

                    match (w1, w2):
                        case (Bool(), Bool()):
                            state.push(w1.eq(w2))
                        case (BV(), BV()):
                            state.push(w1.eq(w2))
                        case (_, _):
                            state.push(BV(w1, size=256).eq(BV(w2, size=256)))

                elif opcode == OP_LT:
                    w1: BV = state.popi()
                    state.set_top(w1.ult(state.topi()))  # bvult

                elif opcode in TERMINATING_OPCODES:
                    if opcode == OP_STOP:
                        ex.halt(data=ByteVec())

                    elif opcode == OP_INVALID:
                        ex.halt(
                            data=ByteVec(),
                            error=InvalidOpcode(opcode),
                        )

                    elif opcode == OP_REVERT:
                        ex.halt(data=ex.ret(), error=Revert())

                    elif opcode == OP_RETURN:
                        ex.halt(data=ex.ret())

                    else:
                        raise ValueError(opcode)

                    yield from finalize(ex)
                    continue

                elif opcode == OP_OR:
                    w1 = state.pop()
                    state.set_top(bitwise(OP_OR, w1, state.top()))

                elif opcode == OP_XOR:
                    w1 = state.popi()
                    state.set_top(w1.bitwise_xor(state.topi()))

                elif opcode == OP_NOT:
                    state.set_top(state.top().bitwise_not())

                elif OP_MUL <= opcode <= OP_SMOD:  # MUL SUB DIV SDIV MOD SMOD
                    w1 = state.popi()
                    state.set_top(self.arith(ex, opcode, w1, state.topi()))

                elif opcode == OP_SLOAD:
                    slot: Word = state.topi()
                    value = self.sload(ex, ex.this(), slot)
                    state.set_top(BV(value, size=256))

                elif opcode == OP_SSTORE:
                    slot: Word = state.popi()
                    value: Word = state.popi()
                    self.sstore(ex, ex.this(), slot, value)

                elif opcode == OP_SHA3:
                    ex.sha3()

                elif opcode == OP_ADDRESS:
                    state.push_any(ex.this())

                elif opcode == OP_BALANCE:
                    state.push_any(ex.balance_of(uint160(state.pop())))

                elif opcode == OP_ORIGIN:
                    state.push_any(ex.origin())

                elif opcode == OP_CALLER:
                    state.push_any(ex.caller())

                elif opcode == OP_CALLVALUE:
                    state.push_any(ex.callvalue())

                elif opcode == OP_CALLDATALOAD:
                    self.calldataload(ex, stack)
                    continue

                elif opcode == OP_CALLDATASIZE:
                    state.push_any(len(ex.calldata()))

                elif opcode == OP_CALLDATACOPY:
                    loc: int = ex.mloc(check_size=False)
                    offset: int = ex.int_of(state.pop(), "symbolic CALLDATACOPY offset")
                    size: int = ex.int_of(state.pop(), "symbolic CALLDATACOPY size")

                    if size:
                        data: ByteVec = ex.message().calldata_slice(offset, size)
                        data = data.concretize(ex.path.concretization.substitution)
                        state.set_mslice(loc, data)

                elif opcode == OP_CODESIZE:
                    state.push_any(len(ex.pgm))

                elif opcode == OP_CODECOPY:
                    loc: int = ex.mloc(check_size=False)
                    offset: int = state.popi()
                    size: int = ex.int_of(state.pop(), "symbolic CODECOPY size")

                    if size:
                        # TODO: hide symbolic support behind a feature flag?
                        # if the offset is symbolic, create a symbolic slice
                        codeslice = (
                            ex.pgm.slice(int(offset), size)
                            if offset.is_concrete
                            else ByteVec(
                                BV(f"codeslice_uint{size * 8}_{uid()}", size=size * 8)
                            )
                        )
                        state.set_mslice(loc, codeslice)

                elif opcode == OP_GAS:
                    state.push_any(f_gas(con(ex.new_gas_id())))

                elif OP_LOG0 <= opcode <= OP_LOG4:
                    if ex.message().is_static:
                        raise WriteInStaticContext(ex.context_str())

                    num_topics: int = opcode - OP_LOG0
                    loc: int = ex.mloc()
                    size: int = ex.int_of(state.pop(), "symbolic LOG data size")
                    topics = list(state.pop() for _ in range(num_topics))
                    data = state.mslice(loc, size)
                    ex.emit_log(EventLog(ex.this(), topics, data))

                elif opcode in CALL_OPCODES:
                    to = uint160(state.peek(2))
                    to_alias = self.resolve_address_alias(ex, to, stack)
                    self.call(ex, opcode, to_alias, stack)
                    continue

                elif opcode in CREATE_OPCODES:
                    self.create(ex, opcode, stack)
                    continue

                elif opcode == OP_RETURNDATASIZE:
                    state.push_any(ex.returndatasize())

                elif opcode == OP_RETURNDATACOPY:
                    loc: int = ex.mloc(check_size=False)
                    offset = ex.int_of(state.pop(), "symbolic RETURNDATACOPY offset")
                    size: int = ex.int_of(state.pop(), "symbolic RETURNDATACOPY size")

                    if size:
                        # no need to check for a huge size because reading out of bounds reverts
                        if offset + size > ex.returndatasize():
                            raise OutOfBoundsRead("RETURNDATACOPY out of bounds")

                        data: ByteVec = ex.returndata().slice(offset, offset + size)
                        state.set_mslice(loc, data)

                elif opcode == OP_BYTE:
                    idx = state.popi()
                    w: BV = state.popi()
                    if idx.is_concrete:
                        state.push(w.byte(idx.value, output_size=256))
                    else:
                        debug_once(
                            f"Warning: the use of symbolic BYTE indexing may potentially "
                            f"impact the performance of symbolic reasoning: BYTE {idx} {w}"
                        )
                        state.push_any(self.sym_byte_of(idx.value, w.as_z3()))

                elif opcode == OP_GASPRICE:
                    state.push_any(f_gasprice())

                elif opcode == OP_EXTCODESIZE:
                    account: BV = uint160(state.peek())
                    account_alias = self.resolve_address_alias(ex, account, stack)
                    state.pop()

                    if account_alias is not None:
                        codesize = BV(len(ex.code[account_alias]))
                    else:
                        # NOTE: the codesize of halmos cheatcode should be non-zero to pass the extcodesize check
                        # for external calls with non-empty return types. this behavior differs from foundry.
                        # the codesize of console is considered zero in foundry
                        codesize = (
                            ONE  # dummy arbitrary value, consistent with foundry
                            if account
                            in [hevm_cheat_code.address, halmos_cheat_code.address]
                            else ZERO
                        )

                    state.push(codesize)

                elif opcode == OP_EXTCODECOPY:
                    account: BV = uint160(state.peek())
                    account_alias = self.resolve_address_alias(ex, account, stack)
                    state.pop()

                    loc: int = ex.int_of(state.pop(), "symbolic EXTCODECOPY offset")
                    offset: int = ex.int_of(state.pop(), "symbolic EXTCODECOPY offset")
                    size: int = ex.int_of(state.pop(), "symbolic EXTCODECOPY size")

                    if size:
                        if account_alias is None:
                            warn(
                                f"EXTCODECOPY: unknown address {hexify(account)} "
                                "is assumed to have empty bytecode"
                            )

                        account_code: Contract | ByteVec = (
                            ex.code.get(account_alias) or ByteVec()
                        )
                        codeslice: ByteVec = account_code.slice(offset, size)
                        state.set_mslice(loc, codeslice)

                elif opcode == OP_EXTCODEHASH:
                    account: BV = uint160(state.peek())
                    account_alias = self.resolve_address_alias(ex, account, stack)
                    state.pop()

                    if account_alias is not None:
                        codehash = BV(
                            ex.sha3_data(ex.code[account_alias]._code.unwrap())
                        )
                    elif account in CHEATCODE_ADDRESSES:
                        # dummy arbitrary value, consistent with foundry
                        codehash = (
                            BV(
                                0xB0450508E5A2349057C3B4C9C84524D62BE4BB17E565DBE2DF34725A26872291
                            )
                            if account == hevm_cheat_code.address
                            else ZERO
                        )
                    else:
                        codehash = ZERO  # vs EMPTY_KECCAK, see EIP-1052
                    state.push(codehash)

                elif opcode == OP_BLOCKHASH:
                    state.push_any(f_blockhash(state.pop()))

                elif opcode == OP_COINBASE:
                    state.push_any(ex.block.coinbase)

                elif opcode == OP_TIMESTAMP:
                    state.push_any(ex.block.timestamp)

                elif opcode == OP_NUMBER:
                    state.push_any(ex.block.number)

                elif opcode == OP_DIFFICULTY:
                    state.push_any(ex.block.difficulty)

                elif opcode == OP_GASLIMIT:
                    state.push_any(ex.block.gaslimit)

                elif opcode == OP_CHAINID:
                    state.push_any(ex.block.chainid)

                elif opcode == OP_SELFBALANCE:
                    state.push_any(ex.balance_of(ex.this()))

                elif opcode == OP_BASEFEE:
                    state.push_any(ex.block.basefee)

                elif opcode == OP_PC:
                    state.push_any(ex.pc)

                elif opcode == OP_MSIZE:
                    size: int = len(state.memory)
                    # round up to the next multiple of 32
                    size = ((size + 31) // 32) * 32
                    state.push_any(size)

                elif opcode == OP_MCOPY:
                    dst_offset = ex.int_of(state.pop(), "symbolic MCOPY dstOffset")
                    src_offset = ex.int_of(state.pop(), "symbolic MCOPY srcOffset")
                    size = ex.int_of(state.pop(), "symbolic MCOPY size")

                    if size:
                        data = state.mslice(src_offset, size)
                        state.set_mslice(dst_offset, data)

                elif opcode == OP_MSTORE8:
                    loc: int = ex.mloc(check_size=True)
                    val: Word = state.pop()
                    state.memory.set_byte(loc, uint8(val))

                elif opcode == OP_TLOAD:
                    slot: Word = state.popi()
                    state.push_any(self.sload(ex, ex.this(), slot, transient=True))

                elif opcode == OP_TSTORE:
                    slot: Word = state.popi()
                    value: Word = state.popi()
                    self.sstore(ex, ex.this(), slot, value, transient=True)

                elif opcode == OP_SLT:
                    w1: BV = state.popi()
                    w2: BV = state.popi()
                    state.push(w1.slt(w2))  # bvslt

                elif opcode == OP_SGT:
                    w1: BV = state.popi()
                    w2: BV = state.popi()
                    state.push(w1.sgt(w2))  # bvsgt

                elif opcode == OP_SAR:
                    w1 = state.popi()
                    w2 = state.popi()
                    state.push(w2.ashr(w1))  # bvashr

                elif opcode == OP_ADDMOD:
                    w1 = state.popi()
                    w2 = state.popi()
                    w3 = state.popi()

                    result = w1.addmod(w2, w3, abstraction=f_mod[w1.size + 8])
                    state.push(result)

                elif opcode == OP_MULMOD:
                    w1 = state.popi()
                    w2 = state.popi()
                    w3 = state.popi()

                    newsize = 2 * w1.size
                    result = w1.mulmod(
                        w2,
                        w3,
                        mul_abstraction=f_mul[newsize],
                        mod_abstraction=f_mod[newsize],
                    )
                    state.push(result)

                elif opcode == OP_EXP:
                    state.push(self.arith(ex, opcode, state.popi(), state.popi()))

                elif opcode == OP_SIGNEXTEND:
                    w1 = ex.int_of(state.popi(), "symbolic SIGNEXTEND size")
                    w2 = state.popi()
                    state.push(w2.signextend(w1))

                else:
                    # TODO: switch to InvalidOpcode when we have full opcode coverage
                    # this halts the path, but we should only halt the current context
                    raise HalmosException(f"Unsupported opcode {mnemonic(opcode)}")

                ex.advance(pc=insn.next_pc)
                next_ex = ex

            except InfeasiblePath:
                # ignore infeasible path
                continue

            except EvmException as err:
                ex.halt(data=ByteVec(), error=err)
                yield from finalize(ex)
                continue

            except HalmosException as err:
                debug(err)
                ex.halt(data=None, error=err)
                yield from finalize(ex)
                continue

            except FailCheatcode as err:
                if not ex.is_halted():
                    # return data shouldn't be None, as it is considered being stuck
                    ex.halt(data=ByteVec(), error=err)
                stack.completed_paths += 1
                yield ex  # early exit; do not call finalize()
                continue

    def mk_exec(
        self,
        #
        code,
        storage,
        transient_storage,
        balance,
        #
        block,
        #
        context: CallContext,
        #
        pgm,
        path,
    ) -> Exec:
        return Exec(
            code=code,
            storage=storage,
            transient_storage=transient_storage,
            balance=balance,
            #
            block=block,
            #
            context=context,
            call_sequence=[],
            callback=None,  # top-level; no callback
            #
            pgm=pgm,
            pc=0,
            st=State(),
            jumpis={},
            #
            path=path,
            alias={},
            #
            log=[],
            cnts=defaultdict(int),
            sha3s=KeccakRegistry(),
            storages={},
            balances={},
        )


# Instruction profiler singleton
class Profiler:
    _instance = None
    _initialized = False

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if not self._initialized:
            self.counters = Counter()
            self._initialized = True

    def increment(self, opcode: int, extra: str = "") -> None:
        key = f"{mnemonic(opcode)}-{extra}" if extra else mnemonic(opcode)
        self.counters[key] += 1

    def get_top_instructions(self, n: int = 20) -> list[tuple[str, int]]:
        """Returns the top n most executed instructions as (mnemonic, count) tuples"""
        return [(key, count) for key, count in self.counters.most_common(n)]

    def reset(self) -> None:
        raise NotImplementedError("Resetting the profiler is not supported")
