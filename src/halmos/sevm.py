# SPDX-License-Identifier: AGPL-3.0

import re
from collections import defaultdict
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
    TypeVar,
)

from eth_hash.auto import keccak
from rich.status import Status
from z3 import (
    UGE,
    UGT,
    ULE,
    ULT,
    And,
    Array,
    ArrayRef,
    BitVec,
    BitVecRef,
    BoolVal,
    CheckSatResult,
    Concat,
    Context,
    Extract,
    Function,
    If,
    LShR,
    Or,
    Select,
    SignExt,
    Solver,
    SRem,
    Store,
    UDiv,
    URem,
    Xor,
    ZeroExt,
    eq,
    is_eq,
    is_false,
    is_true,
    sat,
    simplify,
    unsat,
)
from z3.z3util import is_expr_var

from .bytevec import ByteVec, Chunk, ConcreteChunk, UnwrappedBytes
from .cheatcodes import Prank, halmos_cheat_code, hevm_cheat_code
from .config import Config as HalmosConfig
from .console import console
from .exceptions import (
    AddressCollision,
    EvmException,
    FailCheatcode,
    HalmosException,
    InfeasiblePath,
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
from .logs import (
    INTERNAL_ERROR,
    LIBRARY_PLACEHOLDER,
    debug,
    debug_once,
    warn,
    warn_code,
)
from .utils import (
    EVM,
    Address,
    BitVecSort8,
    BitVecSort160,
    BitVecSort256,
    BitVecSort264,
    BitVecSort512,
    BitVecSorts,
    Byte,
    Bytes,
    Word,
    assert_address,
    assert_bv,
    assert_uint256,
    bv_value_to_bytes,
    byte_length,
    bytes_to_bv_value,
    con,
    con_addr,
    concat,
    create_solver,
    extract_bytes,
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
    is_concrete,
    is_f_sha3_name,
    is_non_zero,
    is_zero,
    match_dynamic_array_overflow_condition,
    restore_precomputed_hashes,
    sha3_inv,
    str_opcode,
    stripped,
    uid,
    uint8,
    uint160,
    uint256,
    unbox_int,
)

Steps = dict[int, dict[str, Any]]  # execution tree

EMPTY_BYTES = ByteVec()
EMPTY_KECCAK = 0xC5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470
ZERO, ONE = con(0), con(1)
MAX_CALL_DEPTH = 1024

# bytes4(keccak256("Panic(uint256)"))
PANIC_SELECTOR = bytes.fromhex("4E487B71")

EMPTY_BALANCE = Array("balance_00", BitVecSort160, BitVecSort256)

# TODO: make this configurable
MAX_MEMORY_SIZE = 2**20
PULSE_INTERVAL = 2**13

FOUNDRY_CALLER = 0x1804C8AB1F12E6BBF3894D4083F33E07309D1F38
FOUNDRY_ORIGIN = FOUNDRY_CALLER
FOUNDRY_TEST = 0x7FA9385BE102AC3EAC297483DD6233D62B3E1496

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
    return f"{pc}:{','.join(jumpdests)}"


def insn_len(opcode: int) -> int:
    return 1 + (opcode - EVM.PUSH0) * (EVM.PUSH1 <= opcode <= EVM.PUSH32)


class Instruction:
    opcode: int
    pc: int = -1
    operand: ByteVec | None = None

    def __init__(self, opcode, pc=-1, operand=None) -> None:
        self.opcode = opcode
        self.pc = pc
        self.operand = operand

    def __str__(self) -> str:
        operand_str = f" {hexify(self.operand)}" if self.operand is not None else ""
        return f"{mnemonic(self.opcode)}{operand_str}"

    def __repr__(self) -> str:
        return f"Instruction({mnemonic(self.opcode)}, pc={self.pc}, operand={repr(self.operand)})"

    def __len__(self) -> int:
        return insn_len(self.opcode)


def id_str(x: Any) -> str:
    return hexify(x).replace(" ", "")


def mnemonic(opcode) -> str:
    if is_concrete(opcode):
        opcode = int_of(opcode)
        return str_opcode.get(opcode, hex(opcode))
    else:
        return str(opcode)


def is_byte(x: Any) -> bool:
    if is_bv(x):
        return eq(x.sort(), BitVecSort8)
    elif isinstance(x, int):
        return 0 <= x < 256
    else:
        return False


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


@dataclass(frozen=True)
class EventLog:
    """
    Data record produced during the execution of a transaction.
    """

    address: Address
    topics: list[Word]
    data: Bytes | None


@dataclass(frozen=True)
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

    def is_create(self) -> bool:
        return self.call_scheme in (EVM.CREATE, EVM.CREATE2)


@dataclass
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


TraceElement = ForwardRef("CallContext") | EventLog


@dataclass
class CallContext:
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


class State:
    stack: list[Word]
    memory: ByteVec

    def __init__(self) -> None:
        self.stack = []
        self.memory = ByteVec()

    def __deepcopy__(self, memo):  # -> State:
        st = State()
        st.stack = self.stack.copy()
        st.memory = self.memory.copy()
        return st

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

    def push(self, v: Word) -> None:
        if isinstance(v, int):
            # TODO: support native types on the stack
            # if not (0 <= v < 2**256):
            #     raise ValueError(v)
            # self.stack.append(v)

            # for now, wrap ints in a BitVec
            self.stack.append(con(v))
        else:
            if not (eq(v.sort(), BitVecSort256) or is_bool(v)):
                raise ValueError(v)
            self.stack.append(simplify(v))

    def pop(self) -> Word:
        if not self.stack:
            raise StackUnderflowError()
        return self.stack.pop()

    def peek(self, n: int = 1) -> Word:
        return self.stack[-n]

    def dup(self, n: int) -> None:
        self.stack.append(self.stack[-n])

    def swap(self, n: int) -> None:
        self.stack[-(n + 1)], self.stack[-1] = self.stack[-1], self.stack[-(n + 1)]

    def mloc(self, subst: dict = None) -> int:
        loc: int = int_of(self.pop(), "symbolic memory offset", subst)
        if loc > MAX_MEMORY_SIZE:
            raise OutOfGasError(f"MLOAD {loc} > MAX_MEMORY_SIZE")
        return loc

    def ret(self, subst: dict = None) -> ByteVec:
        loc: int = self.mloc(subst)
        size: int = int_of(self.pop(), "symbolic return data size", subst)

        returndata_slice = self.memory.slice(loc, loc + size)
        return returndata_slice


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

    _code: ByteVec
    _fastcode: bytes | None
    _insn: dict[int, Instruction]
    _next_pc: dict[int, int]
    _jumpdests: tuple[set] | None

    def __init__(self, code: ByteVec | None = None) -> None:
        if not isinstance(code, ByteVec):
            code = ByteVec(code)

        self._code = code
        self._fastcode = None

        # if the bytecode starts with a concrete prefix, we store it separately for fast access
        # (this is a common case, especially for test contracts that deploy other contracts)
        if code.chunks:
            first_chunk = code.chunks[0]
            if isinstance(first_chunk, ConcreteChunk):
                self._fastcode = first_chunk.unwrap()

        # maps pc to decoded instruction (including operand and next_pc)
        self._insn = dict()
        self._next_pc = dict()
        self._jumpdests = None

    def __deepcopy__(self, memo):
        # the class is essentially immutable (the only mutable fields are caches)
        # so we can return the object itself instead of creating a new copy
        return self

    def __get_jumpdests(self):
        # quick scan, does not eagerly decode instructions
        jumpdests = set()
        jumpdests_str = set()
        pc = 0

        # optimistically process fast path first
        for bytecode in (self._fastcode, self._code):
            if not bytecode:
                continue

            N = len(bytecode)
            while pc < N:
                try:
                    opcode = int_of(bytecode[pc])

                    if opcode == EVM.JUMPDEST:
                        jumpdests.add(pc)

                        # a little odd, but let's add the string representation of the pc as well
                        # because it makes jumpi_id cheaper to compute
                        jumpdests_str.add(str(pc))

                    next_pc = pc + insn_len(opcode)
                    self._next_pc[pc] = next_pc
                    pc = next_pc
                except NotConcreteError:
                    break

        return (jumpdests, jumpdests_str)

    def from_hexcode(hexcode: str):
        """Create a contract from a hexcode string, e.g. "aabbccdd" """
        if not isinstance(hexcode, str):
            raise ValueError(hexcode)

        if len(hexcode) % 2 != 0:
            raise ValueError(hexcode)

        if "__" in hexcode:
            warn_code(
                LIBRARY_PLACEHOLDER, "contract hexcode contains library placeholder"
            )

        try:
            bytecode = bytes.fromhex(stripped(hexcode))
            return Contract(ByteVec(bytecode))
        except ValueError as e:
            raise ValueError(f"{e} (hexcode={hexcode})") from e

    def _decode_instruction(self, pc: int) -> tuple[Instruction, int]:
        opcode = int_of(self[pc], f"symbolic opcode at pc={pc}")
        length = insn_len(opcode)
        next_pc = pc + length

        if length > 1:
            # TODO: consider slicing lazily
            operand = self.unwrapped_slice(pc + 1, next_pc)
            return (Instruction(opcode, pc=pc, operand=operand), next_pc)

        return (Instruction(opcode, pc=pc), next_pc)

    def decode_instruction(self, pc: int) -> Instruction:
        """decode instruction at pc and cache the result"""

        if (insn := self._insn.get(pc)) is None:
            insn, next_pc = self._decode_instruction(pc)
            self._insn[pc] = insn
            self._next_pc[pc] = next_pc

        return insn

    def next_pc(self, pc):
        if (result := self._next_pc.get(pc)) is not None:
            return result

        self.decode_instruction(pc)
        return self._next_pc[pc]

    def slice(self, start, stop) -> ByteVec:
        # fast path for offsets in the concrete prefix
        if self._fastcode and stop < len(self._fastcode):
            return ByteVec(self._fastcode[start:stop])

        return self._code.slice(start, stop)

    def unwrapped_slice(self, start, stop) -> UnwrappedBytes:
        # fast path for offsets in the concrete prefix
        if self._fastcode and stop < len(self._fastcode):
            return self._fastcode[start:stop]

        return self._code.slice(start, stop).unwrap()

    def __getitem__(self, key: int) -> Byte:
        """Returns the byte at the given offset."""
        offset = int_of(key, "symbolic index into contract bytecode {offset!r}")

        # fast path for offsets in the concrete prefix
        if self._fastcode and offset < len(self._fastcode):
            return self._fastcode[offset]

        return self._code.get_byte(offset)

    def __len__(self) -> int:
        """Returns the length of the bytecode in bytes."""
        return len(self._code)

    def valid_jump_destinations(self) -> set[int]:
        """Returns the set of valid jump destinations."""
        if self._jumpdests is None:
            self._jumpdests = self.__get_jumpdests()

        return self._jumpdests[0]

    def valid_jump_destinations_str(self) -> set[str]:
        """Returns the set of valid jump destinations as strings."""
        if self._jumpdests is None:
            self._jumpdests = self.__get_jumpdests()

        return self._jumpdests[1]


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


class Path:
    # a Path object represents a prefix of the path currently being executed
    # initially, it's an empty path at the beginning of execution

    solver: Solver
    num_scopes: int
    # path constraints include both explicit branching conditions and implicit assumptions (eg, no hash collisions)
    conditions: dict  # cond -> bool (true if explicit branching conditions)
    concretization: Concretization
    pending: list

    def __init__(self, solver: Solver):
        self.solver = solver
        self.num_scopes = 0
        self.conditions = {}
        self.concretization = Concretization()
        self.pending = []

    def __deepcopy__(self, memo):
        raise NotImplementedError("use the branch() method instead of deepcopy()")

    def __str__(self) -> str:
        return "".join(
            [
                f"- {cond}\n"
                for cond in self.conditions
                if self.conditions[cond] and not is_true(cond)
            ]
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

        if args.cache_solver:
            # TODO: investigate whether a separate context is necessary here
            tmp_solver = create_solver(ctx=Context())
            for cond in self.conditions:
                tmp_solver.assert_and_track(
                    cond.translate(tmp_solver.ctx), str(cond.get_id())
                )
            query = tmp_solver.to_smt2()
            tmp_solver.reset()
        else:
            query = self.solver.to_smt2()
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
        self.solver.push()

        # shallow copy because existing conditions won't change
        # note: deep copy would be needed later for advanced query optimizations (eg, constant propagation)
        path.conditions = self.conditions.copy()

        path.concretization = deepcopy(self.concretization)

        # store the branching condition aside until the new path is activated.
        path.pending.append(cond)

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

    def append(self, cond, branching=False):
        cond = simplify(cond)

        if is_true(cond):
            return

        if is_false(cond):
            # false shouldn't have been added; raise InfeasiblePath before append() if false
            warn_code(INTERNAL_ERROR, "path.append(false)")

        if cond in self.conditions:
            return

        self.solver.add(cond)
        self.conditions[cond] = branching
        self.concretization.process_cond(cond)

    def extend(self, conds, branching=False):
        for cond in conds:
            self.append(cond, branching=branching)

    def extend_path(self, path):
        # branching conditions are not preserved
        self.extend(path.conditions.keys())


@dataclass
class StorageData:
    symbolic: bool = False
    mapping: dict = field(default_factory=dict)


class Exec:  # an execution path
    # network
    code: dict[Address, Contract]
    storage: dict[Address, StorageData]  # address -> { storage slot -> value }
    balance: Any  # address -> balance

    # block
    block: Block

    # tx
    context: CallContext
    callback: Callable | None  # to be called when returning back to parent context

    # vm state
    pgm: Contract
    pc: int
    st: State  # stack and memory
    jumpis: dict[JumpID, dict[bool, int]]  # for loop detection
    addresses_to_delete: set[Address]

    # path
    path: Path  # path conditions
    alias: dict[Address, Address]  # address aliases

    # internal bookkeeping
    cnts: dict[str, int]  # counters
    sha3s: dict[Word, int]  # sha3 hashes generated
    storages: dict[Any, Any]  # storage updates
    balances: dict[Any, Any]  # balance updates
    known_keys: dict[Any, Any]  # maps address to private key
    known_sigs: dict[Any, Any]  # maps (private_key, digest) to (v, r, s)

    def __init__(self, **kwargs) -> None:
        self.code = kwargs["code"]
        self.storage = kwargs["storage"]
        self.balance = kwargs["balance"]
        #
        self.block = kwargs["block"]
        #
        self.context = kwargs["context"]
        self.callback = kwargs["callback"]
        #
        self.pgm = kwargs["pgm"]
        self.pc = kwargs["pc"]
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
        """
        Check if the error is Panic(k) for any k in the given error code set.
        An empty set or None will match any error code.

        Panic(k) is encoded as 36 bytes (4 + 32) consisting of:
            bytes4(keccak256("Panic(uint256)")) + bytes32(k)
        """

        output = self.context.output

        if not isinstance(output.error, Revert):
            return False

        error_data = output.data
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

    def emit_log(self, log: EventLog):
        self.context.trace.append(log)

    def calldata(self) -> ByteVec:
        message = self.message()
        return Chunk.empty() if message.is_create() else message.data

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
        return unbox_int(self.pgm[self.pc])

    def current_instruction(self) -> Instruction:
        return self.pgm.decode_instruction(self.pc)

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
                    "".join(map(lambda x: f"- {self.sha3s[x]}: {x}\n", self.sha3s)),
                ]
            )
        )

    def advance_pc(self) -> None:
        self.pc = self.pgm.next_pc(self.pc)

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
        assert_address(addr)
        addr = uint160(addr)
        value = self.select(self.balance, addr, self.balances)
        # generate emptyness axiom for each array index, instead of using quantified formula
        self.path.append(Select(EMPTY_BALANCE, addr) == ZERO)
        # practical assumption on the max balance per account
        self.path.append(ULT(value, con(2**96)))
        return value

    def balance_update(self, addr: Word, value: Word) -> None:
        assert_address(addr)
        assert_uint256(value)
        addr = uint160(addr)
        new_balance_var = Array(
            f"balance_{uid()}_{1+len(self.balances):>02}", BitVecSort160, BitVecSort256
        )
        new_balance = Store(self.balance, addr, value)
        self.path.append(new_balance_var == new_balance)
        self.balance = new_balance_var
        self.balances[new_balance_var] = new_balance

    def sha3(self) -> None:
        loc: int = self.mloc()
        size: int = self.int_of(self.st.pop(), "symbolic SHA3 data size")
        data = self.st.memory.slice(loc, loc + size).unwrap() if size else b""
        sha3_image = self.sha3_data(data)
        self.st.push(sha3_image)

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

        if sha3_hash is not None:
            self.path.append(sha3_expr == bytes_to_bv_value(sha3_hash))

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

        # handle create2 hash
        size = byte_length(data)
        if size == 85:
            first_byte = unbox_int(ByteVec(data).get_byte(0))
            if isinstance(first_byte, int) and first_byte == 0xFF:
                return con(create2_magic_address + self.sha3s[sha3_expr])
        else:
            return sha3_expr

    def assume_sha3_distinct(self, sha3_expr) -> None:
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

        self.sha3s[sha3_expr] = len(self.sha3s)

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

    def jumpi_id(self) -> JumpID:
        valid_jumpdests = self.pgm.valid_jump_destinations_str()

        # we call `as_string()` on each stack element to avoid the overhead of
        # calling is_bv_val() followed by as_long() on each element
        jumpdest_tokens = tuple(
            token
            for x in self.st.stack
            if (hasattr(x, "as_string") and (token := x.as_string())) in valid_jumpdests
        )

        # no need to create a new string here, we can compare tuples efficiently
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

    def mloc(self) -> int:
        return self.st.mloc(self.path.concretization.substitution)

    def ret(self) -> ByteVec:
        return self.st.ret(self.path.concretization.substitution)

    def int_of(self, x: Any, err: str = None) -> int:
        return int_of(x, err, self.path.concretization.substitution)


class Storage:
    pass


class SolidityStorage(Storage):
    @classmethod
    def mk_storagedata(cls) -> StorageData:
        return StorageData(mapping=defaultdict(lambda: defaultdict(dict)))

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
        cls, ex: Exec, addr: Any, slot: int, keys: tuple, num_keys: int, size_keys: int
    ) -> None:
        """
        Initialize ex.storage[addr].mapping[slot][num_keys][size_keys], if not yet initialized
        - case size_keys == 0: scalar type: initialized with zero or symbolic value
        - case size_keys != 0: mapping type: initialized with empty array or symbolic array
        """
        assert_address(addr)

        storage_data = ex.storage[addr]
        mapping = storage_data.mapping[slot][num_keys]

        if size_keys in mapping:
            return

        if size_keys > 0:
            # do not use z3 const array `K(BitVecSort(size_keys), ZERO)` when not ex.symbolic
            # instead use normal smt array, and generate emptyness axiom; see load()
            mapping[size_keys] = cls.empty(addr, slot, keys)
            return

        # size_keys == 0
        mapping[size_keys] = (
            BitVec(
                # note: uuid is excluded to be deterministic
                f"storage_{id_str(addr)}_{slot}_{num_keys}_{size_keys}_00",
                BitVecSort256,
            )
            if storage_data.symbolic
            else ZERO
        )

    @classmethod
    def load(cls, ex: Exec, addr: Any, loc: Word) -> Word:
        (slot, keys, num_keys, size_keys) = cls.get_key_structure(ex, loc)

        cls.init(ex, addr, slot, keys, num_keys, size_keys)

        storage_data = ex.storage[addr]
        mapping = storage_data.mapping[slot][num_keys]

        if num_keys == 0:
            return mapping[size_keys]

        symbolic = storage_data.symbolic
        concat_keys = concat(keys)

        if not symbolic:
            # generate emptyness axiom for each array index, instead of using quantified formula; see init()
            default_value = Select(cls.empty(addr, slot, keys), concat_keys)
            ex.path.append(default_value == ZERO)

        return ex.select(mapping[size_keys], concat_keys, ex.storages, symbolic)

    @classmethod
    def store(cls, ex: Exec, addr: Any, loc: Any, val: Any) -> None:
        (slot, keys, num_keys, size_keys) = cls.get_key_structure(ex, loc)

        cls.init(ex, addr, slot, keys, num_keys, size_keys)

        storage_data = ex.storage[addr]
        mapping = storage_data.mapping[slot][num_keys]

        if num_keys == 0:
            mapping[size_keys] = val
            return

        new_storage_var = Array(
            f"storage_{id_str(addr)}_{slot}_{num_keys}_{size_keys}_{uid()}_{1+len(ex.storages):>02}",
            BitVecSorts[size_keys],
            BitVecSort256,
        )
        new_storage = Store(mapping[size_keys], concat(keys), val)
        ex.path.append(new_storage_var == new_storage)

        mapping[size_keys] = new_storage_var
        ex.storages[new_storage_var] = new_storage

    @classmethod
    def get_key_structure(cls, ex, loc) -> tuple:
        offsets = cls.decode(loc)
        if not len(offsets) > 0:
            raise ValueError(offsets)

        slot, keys = ex.int_of(offsets[0], "symbolic storage base slot"), offsets[1:]

        num_keys = len(keys)
        size_keys = cls.bitsize(keys)

        return (slot, keys, num_keys, size_keys)

    @classmethod
    def decode(cls, loc: Any) -> Any:
        loc = normalize(loc)
        # m[k] : hash(k.m)
        if loc.decl().name() == f_sha3_512_name:
            args = loc.arg(0)
            offset = simplify(Extract(511, 256, args))
            base = simplify(Extract(255, 0, args))
            return cls.decode(base) + (offset, ZERO)
        # a[i] : hash(a) + i
        elif loc.decl().name() == f_sha3_256_name:
            base = loc.arg(0)
            return cls.decode(base) + (ZERO,)
        # m[k] : hash(k.m)  where |k| != 256-bit
        elif is_f_sha3_name(loc.decl().name()):
            sha3_input = normalize(loc.arg(0))
            if sha3_input.decl().name() == "concat" and sha3_input.num_args() == 2:
                offset = simplify(sha3_input.arg(0))
                base = simplify(sha3_input.arg(1))
                if offset.size() != 256 and base.size() == 256:
                    return cls.decode(base) + (offset, ZERO)
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
    def init(cls, ex: Exec, addr: Any, loc: BitVecRef, size_keys: int) -> None:
        """
        Initialize ex.storage[addr].mapping[size_keys], if not yet initialized

        NOTE: unlike SolidityStorage, size_keys > 0 in GenericStorage.
              thus it is of mapping type, and initialized with empty array or symbolic array.
        """
        assert_address(addr)

        mapping = ex.storage[addr].mapping

        if size_keys not in mapping:
            mapping[size_keys] = cls.empty(addr, loc)

    @classmethod
    def load(cls, ex: Exec, addr: Any, loc: Word) -> Word:
        loc = cls.decode(loc)
        size_keys = loc.size()

        cls.init(ex, addr, loc, size_keys)

        storage_data = ex.storage[addr]
        mapping = storage_data.mapping
        symbolic = storage_data.symbolic

        if not symbolic:
            # generate emptyness axiom for each array index, instead of using quantified formula; see init()
            default_value = Select(cls.empty(addr, loc), loc)
            ex.path.append(default_value == ZERO)

        return ex.select(mapping[size_keys], loc, ex.storages, symbolic)

    @classmethod
    def store(cls, ex: Exec, addr: Any, loc: Any, val: Any) -> None:
        loc = cls.decode(loc)
        size_keys = loc.size()

        cls.init(ex, addr, loc, size_keys)

        mapping = ex.storage[addr].mapping

        new_storage_var = Array(
            f"storage_{id_str(addr)}_{size_keys}_{uid()}_{1+len(ex.storages):>02}",
            BitVecSorts[size_keys],
            BitVecSort256,
        )
        new_storage = Store(mapping[size_keys], loc, val)
        ex.path.append(new_storage_var == new_storage)

        mapping[size_keys] = new_storage_var
        ex.storages[new_storage_var] = new_storage

    @classmethod
    def decode(cls, loc: Any) -> Any:
        loc = normalize(loc)
        if loc.decl().name() == f_sha3_512_name:  # hash(hi,lo), recursively
            args = loc.arg(0)
            hi = cls.decode(simplify(Extract(511, 256, args)))
            lo = cls.decode(simplify(Extract(255, 0, args)))
            return cls.simple_hash(Concat(hi, lo))
        elif is_f_sha3_name(loc.decl().name()):
            sha3_input = normalize(loc.arg(0))
            if sha3_input.decl().name() == "concat":
                decoded_sha3_input_args = [
                    cls.decode(sha3_input.arg(i)) for i in range(sha3_input.num_args())
                ]
                return cls.simple_hash(concat(decoded_sha3_input_args))
            else:
                return cls.simple_hash(cls.decode(sha3_input))
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
        return bitwise(op, If(x, ONE, ZERO), y)
    elif is_bv(x) and is_bool(y):
        return bitwise(op, x, If(y, ONE, ZERO))
    else:
        raise ValueError(op, x, y)


def b2i(w: Word) -> Word:
    if is_true(w):
        return ONE
    if is_false(w):
        return ZERO
    if is_bool(w):
        return If(w, ONE, ZERO)
    else:
        return w


def is_power_of_two(x: int) -> bool:
    if x > 0:
        return not (x & (x - 1))
    else:
        return False


class HalmosLogs:
    bounded_loops: list[JumpID]

    def __init__(self) -> None:
        self.bounded_loops = []

    def extend(self, logs: "HalmosLogs") -> None:
        self.bounded_loops.extend(logs.bounded_loops)


@dataclass
class WorklistItem:
    ex: Exec
    step: int


class Worklist:
    def __init__(self):
        self.stack = []

        # status data
        self.completed_paths = 0
        self.start_time = timer()

    def push(self, ex: Exec, step: int):
        self.stack.append(WorklistItem(ex, step))

    def pop(self) -> WorklistItem:
        return self.stack.pop()

    def __len__(self) -> int:
        return len(self.stack)


class SEVM:
    options: HalmosConfig
    storage_model: type[SomeStorage]
    logs: HalmosLogs
    steps: Steps

    def __init__(self, options: HalmosConfig) -> None:
        self.options = options
        self.logs = HalmosLogs()
        self.steps: Steps = {}

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

    def mk_mul(self, ex: Exec, x: Any, y: Any) -> Any:
        term = f_mul[x.size()](x, y)
        return term

    def arith(self, ex: Exec, op: int, w1: Word, w2: Word) -> Word:
        w1 = b2i(w1)
        w2 = b2i(w2)

        if op == EVM.ADD:
            return w1 + w2

        if op == EVM.SUB:
            return w1 - w2

        if op == EVM.MUL:
            is_bv_value_w1 = is_bv_value(w1)
            is_bv_value_w2 = is_bv_value(w2)

            if is_bv_value_w1 and is_bv_value_w2:
                return w1 * w2

            if is_bv_value_w1:
                i1: int = w1.as_long()
                if i1 == 0:
                    return w1

                if i1 == 1:
                    return w2

                if is_power_of_two(i1):
                    return w2 << (i1.bit_length() - 1)

            if is_bv_value_w2:
                i2: int = w2.as_long()
                if i2 == 0:
                    return w2

                if i2 == 1:
                    return w1

                if is_power_of_two(i2):
                    return w1 << (i2.bit_length() - 1)

            if is_bv_value_w1 or is_bv_value_w2:
                return w1 * w2

            return self.mk_mul(ex, w1, w2)

        if op == EVM.DIV:
            div_for_overflow_check = self.div_xy_y(w1, w2)
            if div_for_overflow_check is not None:  # xy/x or xy/y
                return div_for_overflow_check

            if is_bv_value(w1) and is_bv_value(w2):
                if w2.as_long() == 0:
                    return w2
                else:
                    return UDiv(w1, w2)  # unsigned div (bvudiv)

            if is_bv_value(w2):
                # concrete denominator case
                i2: int = w2.as_long()
                if i2 == 0:
                    return w2

                if i2 == 1:
                    return w1

                if is_power_of_two(i2):
                    return LShR(w1, i2.bit_length() - 1)

            return self.mk_div(ex, w1, w2)

        if op == EVM.MOD:
            if is_bv_value(w1) and is_bv_value(w2):
                if w2.as_long() == 0:
                    return w2
                else:
                    return URem(w1, w2)  # bvurem

            if is_bv_value(w2):
                i2: int = int(str(w2))
                if i2 == 0 or i2 == 1:
                    return con(0, w2.size())

                if is_power_of_two(i2):
                    bitsize = i2.bit_length() - 1
                    return ZeroExt(w2.size() - bitsize, Extract(bitsize - 1, 0, w1))

            return self.mk_mod(ex, w1, w2)

        if op == EVM.SDIV:
            if is_bv_value(w1) and is_bv_value(w2):
                if w2.as_long() == 0:
                    return w2
                else:
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
                if w2.as_long() == 0:
                    return w2
                else:
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
                    return ONE

                if i2 == 1:
                    return w1

                if i2 <= self.options.smt_exp_by_const:
                    exp = w1
                    for _ in range(i2 - 1):
                        exp = self.arith(ex, EVM.MUL, exp, w1)
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

    def mk_storagedata(self) -> StorageData:
        return self.storage_model.mk_storagedata()

    def sload(self, ex: Exec, addr: Any, loc: Word) -> Word:
        return self.storage_model.load(ex, addr, loc)

    def sstore(self, ex: Exec, addr: Any, loc: Any, val: Any) -> None:
        if ex.message().is_static:
            raise WriteInStaticContext(ex.context_str())

        if is_bool(val):
            val = If(val, ONE, ZERO)

        self.storage_model.store(ex, addr, loc, val)

    def resolve_address_alias(
        self, ex: Exec, target: Address, stack, step_id, allow_branching=True
    ) -> Address:
        assert_bv(target)
        assert_address(target)

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
            if addr == FOUNDRY_TEST:
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
            stack.push(new_ex, step_id)

        addr, cond = head
        ex.path.append(cond, branching=True)
        ex.alias[target] = addr
        return addr

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
        if is_false(balance_cond):
            raise InfeasiblePath("transfer_value: balance is not enough")
        ex.path.append(balance_cond)

        # conditional transfer
        if condition is not None:
            value = If(condition, value, ZERO)

        ex.balance_update(caller, self.arith(ex, EVM.SUB, ex.balance_of(caller), value))
        ex.balance_update(to, self.arith(ex, EVM.ADD, ex.balance_of(to), value))

    def call(
        self,
        ex: Exec,
        op: int,
        to_alias: Address,
        stack: list[tuple[Exec, int]],
        step_id: int,
    ) -> None:
        # `to`: the original (symbolic) target address
        # `to_alias`: a (concrete) alias of the target considered in this path.
        #            it could be None, indicating a non-existent address.

        ex.st.pop()  # gas
        to = uint160(ex.st.pop())
        fund = ZERO if op in [EVM.STATICCALL, EVM.DELEGATECALL] else ex.st.pop()

        arg_loc: int = ex.mloc()
        arg_size: int = ex.int_of(ex.st.pop(), "symbolic CALL input data size")

        ret_loc: int = ex.mloc()
        ret_size: int = ex.int_of(ex.st.pop(), "symbolic CALL return data size")

        if not arg_size >= 0:
            raise ValueError(arg_size)

        if not ret_size >= 0:
            raise ValueError(ret_size)

        pranked_caller, pranked_origin = ex.resolve_prank(to)
        arg = ex.st.memory.slice(arg_loc, arg_loc + arg_size)

        def send_callvalue(condition=None) -> None:
            # no balance update for CALLCODE which transfers to itself
            if op == EVM.CALL:
                # TODO: revert if context is static
                # NOTE: we cannot use `to_alias` here because it could be None
                self.transfer_value(ex, pranked_caller, to, fund, condition)

        def call_known(to: Address) -> None:
            # backup current state
            orig_code = ex.code.copy()
            orig_storage = deepcopy(ex.storage)
            orig_balance = ex.balance

            # transfer msg.value
            send_callvalue()

            message = Message(
                target=to if op in [EVM.CALL, EVM.STATICCALL] else ex.this(),
                caller=pranked_caller if op != EVM.DELEGATECALL else ex.caller(),
                origin=pranked_origin,
                value=fund if op != EVM.DELEGATECALL else ex.callvalue(),
                data=arg,
                is_static=(ex.context.message.is_static or op == EVM.STATICCALL),
                call_scheme=op,
            )

            def callback(new_ex: Exec, stack, step_id):
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
                new_ex.st = deepcopy(ex.st)
                new_ex.jumpis = deepcopy(ex.jumpis)

                # set return data (in memory)
                effective_ret_size = min(ret_size, new_ex.returndatasize())
                if effective_ret_size > 0:
                    returndata_slice = subcall.output.data.slice(0, effective_ret_size)
                    end_loc = ret_loc + effective_ret_size
                    if end_loc > MAX_MEMORY_SIZE:
                        raise HalmosException("returned data exceeds MAX_MEMORY_SIZE")

                    new_ex.st.memory.set_slice(ret_loc, end_loc, returndata_slice)

                # set status code on the stack
                subcall_success = subcall.output.error is None
                new_ex.st.push(1 if subcall_success else 0)

                if not subcall_success:
                    # revert network states
                    new_ex.code = orig_code.copy()
                    new_ex.storage = deepcopy(orig_storage)
                    new_ex.balance = orig_balance

                # add to worklist even if it reverted during the external call
                new_ex.advance_pc()
                stack.push(new_ex, step_id)

            sub_ex = Exec(
                code=ex.code,
                storage=ex.storage,
                balance=ex.balance,
                #
                block=ex.block,
                #
                context=CallContext(message=message, depth=ex.context.depth + 1),
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

            stack.push(sub_ex, step_id)

        def call_unknown() -> None:
            # ecrecover
            if eq(to, con_addr(1)):
                # TODO: explicitly return empty data in case of an error
                # TODO: validate input and fork on error?
                # - v in [27, 28]
                # - r, s in [1, secp256k1n)

                # call never fails, errors result in empty returndata
                exit_code = ONE

                digest = extract_bytes(arg, 0, 32)
                v = uint8(extract_bytes(arg, 32, 32))
                r = extract_bytes(arg, 64, 32)
                s = extract_bytes(arg, 96, 32)

                # TODO: empty returndata in error
                ret = ByteVec(uint256(f_ecrecover(digest, v, r, s)))

            # sha256
            elif eq(to, con_addr(2)):
                exit_code = con(1)
                f_sha256 = Function(
                    f"f_sha256_{arg_size}", BitVecSorts[arg_size], BitVecSort256
                )
                ret = ByteVec(f_sha256(arg))

            # ripemd160
            elif eq(to, con_addr(3)):
                exit_code = con(1)
                f_ripemd160 = Function(
                    f"f_ripemd160_{arg_size}", BitVecSorts[arg_size], BitVecSort160
                )
                ret = ByteVec(uint256(f_ripemd160(arg)))

            # identity
            elif eq(to, con_addr(4)):
                exit_code = ONE
                ret = arg

            # modexp
            elif eq(to, con_addr(5)):
                exit_code = con(1)
                modulus_size = ex.int_of(extract_bytes(arg, 64, 32))
                f_modexp = Function(
                    f"f_modexp_{arg_size}_{modulus_size}",
                    BitVecSorts[arg_size],
                    BitVecSorts[modulus_size],
                )
                # TODO: empty returndata in error
                ret = ByteVec(f_modexp(arg))

            # ecadd
            elif eq(to, con_addr(6)):
                exit_code = con(1)
                f_ecadd = Function("f_ecadd", BitVecSorts[1024], BitVecSorts[512])
                ret = ByteVec(f_ecadd(arg))

            # ecmul
            elif eq(to, con_addr(7)):
                exit_code = con(1)
                f_ecmul = Function("f_ecmul", BitVecSorts[768], BitVecSorts[512])
                ret = ByteVec(f_ecmul(arg))

            # ecpairing
            elif eq(to, con_addr(8)):
                exit_code = con(1)
                f_ecpairing = Function("f_ecpairing", BitVecSorts[1536], BitVecSorts[1])
                ret = ByteVec(uint256(f_ecpairing(arg)))

            # blake2f
            elif eq(to, con_addr(9)):
                exit_code = con(1)
                f_blake2f = Function("f_blake2f", BitVecSorts[1704], BitVecSorts[512])
                ret = ByteVec(f_blake2f(arg))

            # point_evaluation
            elif eq(to, con_addr(10)):
                exit_code = con(1)
                f_point_evaluation = Function(
                    "f_point_evaluation", BitVecSorts[1544], BitVecSorts[512]
                )
                ret = ByteVec(f_point_evaluation(arg))

            # halmos cheat code
            elif eq(to, halmos_cheat_code.address):
                exit_code = ONE
                ret = halmos_cheat_code.handle(self, ex, arg, stack, step_id)

            # vm cheat code
            elif eq(to, hevm_cheat_code.address):
                exit_code = ONE
                ret = hevm_cheat_code.handle(self, ex, arg, stack, step_id)

            # console
            elif eq(to, console.address):
                exit_code = ONE
                console.handle(ex, arg)
                ret = ByteVec()

            # non-existing contracts
            else:
                # in evm, calls to non-existing contracts always succeed with empty returndata
                # TODO: exitcode should be 0 when balance is not enough for callvalue
                exit_code = con(1)
                ret = ByteVec()

            # push exit code
            exit_code_var = BitVec(
                f"call_exit_code_{uid()}_{ex.new_call_id():>02}", BitVecSort256
            )
            ex.path.append(exit_code_var == exit_code)
            ex.st.push(exit_code if is_bv_value(exit_code) else exit_code_var)

            # transfer msg.value
            send_callvalue(exit_code_var != ZERO)

            ret_lst = ret if isinstance(ret, list) else [ret]

            last_idx = len(ret_lst) - 1
            for idx, ret_ in enumerate(ret_lst):
                new_ex = (
                    self.create_branch(ex, BoolVal(True), ex.pc)
                    if idx < last_idx
                    else ex
                )

                # TODO: refactor this return memory setting to be shared with call_known()
                # store return value
                effective_ret_size = min(ret_size, len(ret_))
                if effective_ret_size > 0:
                    end_loc = ret_loc + effective_ret_size
                    if end_loc > MAX_MEMORY_SIZE:
                        raise HalmosException("returned data exceeds MAX_MEMORY_SIZE")

                    new_ex.st.memory.set_slice(ret_loc, end_loc, ret_)

                if not isinstance(ret_, ByteVec):
                    raise HalmosException(f"Invalid return value: {ret_}")

                new_ex.context.trace.append(
                    CallContext(
                        # TODO: refactor this message to be shared with call_known()
                        message=Message(
                            target=to,
                            caller=pranked_caller,
                            origin=pranked_origin,
                            value=fund,
                            data=new_ex.st.memory.slice(arg_loc, arg_loc + arg_size),
                            call_scheme=op,
                        ),
                        output=CallOutput(
                            data=ret_,
                            error=None,
                        ),
                        depth=new_ex.context.depth + 1,
                    )
                )

                new_ex.advance_pc()
                stack.push(new_ex, step_id)

        # precompiles or cheatcodes
        if (
            # precompile
            (is_bv_value(to) and to.as_long() in range(1, 11))
            # cheatcode calls
            or eq(to, halmos_cheat_code.address)
            or eq(to, hevm_cheat_code.address)
            or eq(to, console.address)
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
        stack: list[tuple[Exec, int]],
        step_id: int,
    ) -> None:
        if ex.message().is_static:
            raise WriteInStaticContext(ex.context_str())

        value: Word = ex.st.pop()
        loc: int = ex.int_of(ex.st.pop(), "symbolic CREATE offset")
        size: int = ex.int_of(ex.st.pop(), "symbolic CREATE size")

        if op == EVM.CREATE2:
            salt = ex.st.pop()

        # check if there is an active prank
        pranked_caller, pranked_origin = ex.resolve_prank(con_addr(0))

        # contract creation code
        create_hexcode = ex.st.memory.slice(loc, loc + size)
        create_code = Contract(create_hexcode)

        # new account address
        if op == EVM.CREATE:
            new_addr = ex.new_address()
        elif op == EVM.CREATE2:  # EVM.CREATE2
            # create_hexcode must be z3 expression to be passed into sha3_data
            create_hexcode = create_hexcode.unwrap()

            if is_bv(create_hexcode):
                create_hexcode = simplify(create_hexcode)
            else:
                create_hexcode = bytes_to_bv_value(create_hexcode)

            code_hash = ex.sha3_data(create_hexcode)
            hash_data = simplify(
                Concat(con(0xFF, 8), uint160(pranked_caller), salt, code_hash)
            )
            new_addr = uint160(ex.sha3_data(hash_data))
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

        if new_addr in ex.code:
            # address conflicts don't revert, they push 0 on the stack and continue
            ex.st.push(0)
            ex.advance_pc()

            # add a virtual subcontext to the trace for debugging purposes
            subcall = CallContext(message=message, depth=ex.context.depth + 1)
            subcall.output.data = ByteVec()
            subcall.output.error = AddressCollision()
            ex.context.trace.append(subcall)

            stack.push(ex, step_id)
            return

        for addr in ex.code:
            ex.path.append(new_addr != addr)  # ensure new address is fresh

        # backup current state
        orig_code = ex.code.copy()
        orig_storage = deepcopy(ex.storage)
        orig_balance = ex.balance

        # setup new account
        ex.set_code(new_addr, Contract(b""))  # existing code must be empty

        # existing storage may not be empty and reset here
        ex.storage[new_addr] = self.mk_storagedata()

        # transfer value
        self.transfer_value(ex, pranked_caller, new_addr, value)

        def callback(new_ex: Exec, stack, step_id):
            subcall = new_ex.context

            # continue execution in the context of the parent
            # pessimistic copy because the subcall results may diverge
            new_ex.context = deepcopy(ex.context)
            new_ex.context.trace.append(subcall)
            new_ex.callback = ex.callback

            # restore vm state
            new_ex.pgm = ex.pgm
            new_ex.pc = ex.pc
            new_ex.st = deepcopy(ex.st)
            new_ex.jumpis = deepcopy(ex.jumpis)

            if subcall.is_stuck():
                # internal errors abort the current path,
                stack.completed_paths += 1
                yield new_ex
                return

            elif subcall.output.error is None:
                # new contract code, will revert if data is None
                new_ex.set_code(new_addr, Contract(subcall.output.data))

                # push new address to stack
                new_ex.st.push(uint256(new_addr))

            else:
                # creation failed
                new_ex.st.push(0)

                # revert network states
                new_ex.code = orig_code.copy()
                new_ex.storage = deepcopy(orig_storage)
                new_ex.balance = orig_balance

            # add to worklist
            new_ex.advance_pc()
            stack.push(new_ex, step_id)

        sub_ex = Exec(
            code=ex.code,
            storage=ex.storage,
            balance=ex.balance,
            #
            block=ex.block,
            #
            context=CallContext(message=message, depth=ex.context.depth + 1),
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

        stack.push(sub_ex, step_id)

    def jumpi(
        self,
        ex: Exec,
        stack: list[tuple[Exec, int]],
        step_id: int,
    ) -> None:
        jid = ex.jumpi_id()

        target: int = ex.int_of(ex.st.pop(), "symbolic JUMPI target")
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
            follow_true = visited[True] < self.options.loop
            follow_false = visited[False] < self.options.loop
            if not (follow_true and follow_false):
                self.logs.bounded_loops.append(jid)
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
            if follow_false:
                new_ex_true = self.create_branch(ex, cond_true, target)
            else:
                new_ex_true = ex
                new_ex_true.path.append(cond_true, branching=True)
                new_ex_true.pc = target

        if follow_false:
            new_ex_false = ex
            new_ex_false.path.append(cond_false, branching=True)
            new_ex_false.advance_pc()

        if new_ex_true:
            if potential_true and potential_false:
                new_ex_true.jumpis[jid] = {
                    True: visited[True] + 1,
                    False: visited[False],
                }
            stack.push(new_ex_true, step_id)

        if new_ex_false:
            if potential_true and potential_false:
                new_ex_false.jumpis[jid] = {
                    True: visited[True],
                    False: visited[False] + 1,
                }
            stack.push(new_ex_false, step_id)

    def jump(self, ex: Exec, stack: list[tuple[Exec, int]], step_id: int) -> None:
        dst = ex.st.pop()

        # if dst is concrete, just jump
        if is_concrete(dst):
            ex.pc = int_of(dst)
            stack.push(ex, step_id)

        # otherwise, create a new execution for feasible targets
        elif self.options.symbolic_jump:
            for target in ex.pgm.valid_jump_destinations():
                target_reachable = simplify(dst == target)
                if ex.check(target_reachable) != unsat:  # jump
                    new_ex = self.create_branch(ex, target_reachable, target)
                    stack.push(new_ex, step_id)
        else:
            raise NotConcreteError(f"symbolic JUMP target: {dst}")

    def create_branch(self, ex: Exec, cond: BitVecRef, target: int) -> Exec:
        new_path = ex.path.branch(cond)
        new_ex = Exec(
            code=ex.code.copy(),  # shallow copy for potential new contract creation; existing code doesn't change
            storage=deepcopy(ex.storage),
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
        )
        return new_ex

    def calldataload(
        self,
        ex: Exec,
        stack: list[tuple[Exec, int]],
        step_id: int,
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
                    new_ex.st.push(candidate)
                    new_ex.advance_pc()
                    stack.push(new_ex, step_id)
                return

        ex.st.push(loaded)
        ex.advance_pc()
        stack.push(ex, step_id)

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

    def run(self, ex0: Exec) -> Iterator[Exec]:
        with Status("") as status:
            yield from self._run(ex0, status)

    def _run(self, ex0: Exec, status: Status) -> Iterator[Exec]:
        step_id: int = 0
        stack: Worklist = Worklist()
        stack.push(ex0, 0)

        def finalize(ex: Exec):
            # if it's at the top-level, there is no callback; yield the current execution state
            if ex.callback is None:
                stack.completed_paths += 1
                yield ex

            # otherwise, execute the callback to return to the parent execution context
            # note: `yield from` is used as the callback may yield the current execution state that got stuck
            else:
                yield from ex.callback(ex, stack, step_id)

        while stack:
            try:
                item = stack.pop()
                ex: Exec = item.ex
                prev_step_id: int = item.step
                step_id += 1

                # display progress
                if not self.options.no_status and step_id % PULSE_INTERVAL == 0:
                    elapsed = timer() - stack.start_time
                    speed = step_id / elapsed

                    # hh:mm:ss
                    elapsed_fmt = timedelta(seconds=int(elapsed))

                    status.update(
                        f"[{elapsed_fmt}] {speed:.0f} ops/s"
                        f" | completed paths: {stack.completed_paths}"
                        f" | outstanding paths: {len(stack)}"
                    )

                if not ex.path.is_activated():
                    ex.path.activate()

                # PathEndingException may not be immediately raised; it could be delayed until it comes out of the worklist
                # see the assert cheatcode hanlder logic for the delayed case
                if isinstance(ex.context.output.error, PathEndingException):
                    raise ex.context.output.error

                if ex.context.depth > MAX_CALL_DEPTH:
                    raise MessageDepthLimitError(ex.context)

                insn = ex.current_instruction()
                opcode = insn.opcode

                if (max_depth := self.options.depth) and step_id > max_depth:
                    continue

                # TODO: clean up
                if self.options.log:
                    if opcode == EVM.JUMPI:
                        self.steps[step_id] = {"parent": prev_step_id, "exec": str(ex)}
                    # elif opcode == EVM.CALL:
                    #     self.steps[step_id] = {'parent': prev_step_id, 'exec': str(ex) + ex.st.str_memory() + '\n'}
                    else:
                        # self.steps[step_id] = {'parent': prev_step_id, 'exec': ex.summary()}
                        self.steps[step_id] = {"parent": prev_step_id, "exec": str(ex)}

                if self.options.print_steps:
                    print(ex.dump(print_mem=self.options.print_mem))

                if opcode in [EVM.STOP, EVM.INVALID, EVM.REVERT, EVM.RETURN]:
                    if opcode == EVM.STOP:
                        ex.halt(data=ByteVec())
                    elif opcode == EVM.INVALID:
                        ex.halt(
                            data=ByteVec(),
                            error=InvalidOpcode(opcode),
                        )
                    elif opcode == EVM.REVERT:
                        ex.halt(data=ex.ret(), error=Revert())
                    elif opcode == EVM.RETURN:
                        ex.halt(data=ex.ret())
                    else:
                        raise ValueError(opcode)

                    yield from finalize(ex)
                    continue

                elif opcode == EVM.JUMPI:
                    self.jumpi(ex, stack, step_id)
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
                            ex.st.push(If(w1, ONE, ZERO) == w2)
                        else:
                            if not is_bv(w1):
                                raise ValueError(w1)
                            if not is_bool(w2):
                                raise ValueError(w2)
                            ex.st.push(w1 == If(w2, ONE, ZERO))
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
                    w = ex.int_of(ex.st.pop(), "symbolic SIGNEXTEND size")
                    if w <= 30:  # if w == 31, result is SignExt(0, value) == value
                        bl = (w + 1) * 8
                        ex.st.push(SignExt(256 - bl, Extract(bl - 1, 0, ex.st.pop())))

                elif opcode == EVM.CALLDATALOAD:
                    self.calldataload(ex, stack, step_id)
                    continue

                elif opcode == EVM.CALLDATASIZE:
                    ex.st.push(len(ex.calldata()))

                elif opcode == EVM.CALLVALUE:
                    ex.st.push(ex.callvalue())

                elif opcode == EVM.CALLER:
                    ex.st.push(uint256(ex.caller()))

                elif opcode == EVM.ORIGIN:
                    ex.st.push(uint256(ex.origin()))

                elif opcode == EVM.ADDRESS:
                    ex.st.push(uint256(ex.this()))

                elif opcode == EVM.EXTCODESIZE:
                    account = uint160(ex.st.peek())
                    account_alias = self.resolve_address_alias(
                        ex, account, stack, step_id
                    )
                    ex.st.pop()

                    if account_alias is not None:
                        codesize = len(ex.code[account_alias])
                    else:
                        codesize = (
                            1  # dummy arbitrary value, consistent with foundry
                            if eq(account, hevm_cheat_code.address)
                            # NOTE: the codesize of halmos cheatcode should be non-zero to pass the extcodesize check for external calls with non-empty return types. this behavior differs from foundry.
                            or eq(account, halmos_cheat_code.address)
                            # the codesize of console is considered zero in foundry
                            # or eq(account, console.address)
                            else 0
                        )

                    ex.st.push(codesize)

                elif opcode == EVM.EXTCODECOPY:
                    account: Address = uint160(ex.st.peek())
                    account_alias = self.resolve_address_alias(
                        ex, account, stack, step_id
                    )
                    ex.st.pop()

                    loc: int = ex.int_of(ex.st.pop(), "symbolic EXTCODECOPY offset")
                    offset: int = ex.int_of(ex.st.pop(), "symbolic EXTCODECOPY offset")
                    size: int = ex.int_of(ex.st.pop(), "symbolic EXTCODECOPY size")

                    if size > 0:
                        end_loc = loc + size
                        if end_loc > MAX_MEMORY_SIZE:
                            raise HalmosException("EXTCODECOPY > MAX_MEMORY_SIZE")

                        if account_alias is None:
                            warn(
                                f"EXTCODECOPY: unknown address {hexify(account)} "
                                "is assumed to have empty bytecode"
                            )

                        account_code: Contract = ex.code.get(account_alias) or ByteVec()
                        codeslice: ByteVec = account_code._code.slice(
                            offset, offset + size
                        )
                        ex.st.memory.set_slice(loc, end_loc, codeslice)

                elif opcode == EVM.EXTCODEHASH:
                    account = uint160(ex.st.peek())
                    account_alias = self.resolve_address_alias(
                        ex, account, stack, step_id
                    )
                    ex.st.pop()

                    if account_alias is not None:
                        codehash = ex.sha3_data(ex.code[account_alias]._code.unwrap())
                    elif (
                        eq(account, hevm_cheat_code.address)
                        or eq(account, halmos_cheat_code.address)
                        or eq(account, console.address)
                    ):
                        # dummy arbitrary value, consistent with foundry
                        codehash = (
                            0xB0450508E5A2349057C3B4C9C84524D62BE4BB17E565DBE2DF34725A26872291
                            if eq(account, hevm_cheat_code.address)
                            else 0
                        )
                    else:
                        codehash = 0  # vs EMPTY_KECCAK, see EIP-1052

                    ex.st.push(codehash)

                elif opcode == EVM.CODESIZE:
                    ex.st.push(len(ex.pgm))

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
                    ex.st.push(ex.pc)

                elif opcode == EVM.BLOCKHASH:
                    ex.st.push(f_blockhash(ex.st.pop()))

                elif opcode == EVM.BALANCE:
                    ex.st.push(ex.balance_of(uint160(ex.st.pop())))

                elif opcode == EVM.SELFBALANCE:
                    ex.st.push(ex.balance_of(ex.this()))

                elif opcode in [
                    EVM.CALL,
                    EVM.CALLCODE,
                    EVM.DELEGATECALL,
                    EVM.STATICCALL,
                ]:
                    to = uint160(ex.st.peek(2))
                    to_alias = self.resolve_address_alias(ex, to, stack, step_id)

                    self.call(ex, opcode, to_alias, stack, step_id)
                    continue

                elif opcode == EVM.SHA3:
                    ex.sha3()

                elif opcode in [EVM.CREATE, EVM.CREATE2]:
                    self.create(ex, opcode, stack, step_id)
                    continue

                elif opcode == EVM.POP:
                    ex.st.pop()

                elif opcode == EVM.MLOAD:
                    loc: int = ex.mloc()
                    ex.st.push(ex.st.memory.get_word(loc))

                elif opcode == EVM.MSTORE:
                    loc: int = ex.mloc()
                    val: Word = ex.st.pop()
                    ex.st.memory.set_word(loc, uint256(val))

                elif opcode == EVM.MSTORE8:
                    loc: int = ex.mloc()
                    val: Word = ex.st.pop()
                    ex.st.memory.set_byte(loc, uint8(val))

                elif opcode == EVM.MSIZE:
                    size: int = len(ex.st.memory)
                    # round up to the next multiple of 32
                    size = ((size + 31) // 32) * 32
                    ex.st.push(size)

                elif opcode == EVM.SLOAD:
                    slot: Word = ex.st.pop()
                    ex.st.push(self.sload(ex, ex.this(), slot))

                elif opcode == EVM.SSTORE:
                    slot: Word = ex.st.pop()
                    value: Word = ex.st.pop()
                    self.sstore(ex, ex.this(), slot, value)

                elif opcode == EVM.RETURNDATASIZE:
                    ex.st.push(ex.returndatasize())

                elif opcode == EVM.RETURNDATACOPY:
                    loc: int = ex.mloc()
                    offset = ex.int_of(ex.st.pop(), "symbolic RETURNDATACOPY offset")
                    size: int = ex.int_of(ex.st.pop(), "symbolic RETURNDATACOPY size")
                    end_loc = loc + size

                    if end_loc > MAX_MEMORY_SIZE:
                        raise HalmosException("RETURNDATACOPY > MAX_MEMORY_SIZE")

                    if size > 0:
                        if offset + size > ex.returndatasize():
                            raise OutOfBoundsRead("RETURNDATACOPY out of bounds")

                        data: ByteVec = ex.returndata().slice(offset, offset + size)
                        ex.st.memory.set_slice(loc, end_loc, data)

                elif opcode == EVM.CALLDATACOPY:
                    loc: int = ex.mloc()
                    offset: int = ex.int_of(ex.st.pop(), "symbolic CALLDATACOPY offset")
                    size: int = ex.int_of(ex.st.pop(), "symbolic CALLDATACOPY size")
                    end_loc = loc + size

                    if end_loc > MAX_MEMORY_SIZE:
                        raise HalmosException("CALLDATACOPY > MAX_MEMORY_SIZE")

                    if size > 0:
                        data: ByteVec = ex.calldata().slice(offset, offset + size)
                        data = data.concretize(ex.path.concretization.substitution)
                        ex.st.memory.set_slice(loc, end_loc, data)

                elif opcode == EVM.CODECOPY:
                    loc: int = ex.mloc()
                    offset: int = ex.int_of(ex.st.pop(), "symbolic CODECOPY offset")
                    size: int = ex.int_of(ex.st.pop(), "symbolic CODECOPY size")
                    end_loc = loc + size

                    if end_loc > MAX_MEMORY_SIZE:
                        raise HalmosException("CODECOPY > MAX_MEMORY_SIZE")

                    if size > 0:
                        codeslice: ByteVec = ex.pgm.slice(offset, offset + size)
                        ex.st.memory.set_slice(loc, loc + size, codeslice)

                elif opcode == EVM.MCOPY:
                    dest_offset = ex.int_of(ex.st.pop(), "symbolic MCOPY destOffset")
                    src_offset = ex.int_of(ex.st.pop(), "symbolic MCOPY srcOffset")
                    size = ex.int_of(ex.st.pop(), "symbolic MCOPY size")

                    if size > 0:
                        src_end_loc = src_offset + size
                        dst_end_loc = dest_offset + size

                        if max(src_end_loc, dst_end_loc) > MAX_MEMORY_SIZE:
                            raise HalmosException("MCOPY > MAX_MEMORY_SIZE")

                        data = ex.st.memory.slice(src_offset, src_end_loc)
                        ex.st.memory.set_slice(dest_offset, dst_end_loc, data)

                elif opcode == EVM.BYTE:
                    idx = ex.st.pop()
                    w = ex.st.pop()
                    if is_bv_value(idx):
                        idx = idx.as_long()
                        if idx < 0:
                            raise ValueError(idx)
                        if idx >= 32:
                            ex.st.push(0)
                        else:
                            ex.st.push(
                                ZeroExt(
                                    248, Extract((31 - idx) * 8 + 7, (31 - idx) * 8, w)
                                )
                            )
                    else:
                        debug_once(
                            f"Warning: the use of symbolic BYTE indexing may potentially "
                            f"impact the performance of symbolic reasoning: BYTE {idx} {w}"
                        )
                        ex.st.push(self.sym_byte_of(idx, w))

                elif EVM.LOG0 <= opcode <= EVM.LOG4:
                    if ex.message().is_static:
                        raise WriteInStaticContext(ex.context_str())

                    num_topics: int = opcode - EVM.LOG0
                    loc: int = ex.mloc()
                    size: int = ex.int_of(ex.st.pop(), "symbolic LOG data size")
                    topics = list(ex.st.pop() for _ in range(num_topics))
                    data = ex.st.memory.slice(loc, loc + size)
                    ex.emit_log(EventLog(ex.this(), topics, data))

                elif opcode == EVM.PUSH0:
                    ex.st.push(0)

                elif EVM.PUSH1 <= opcode <= EVM.PUSH32:
                    val = unbox_int(insn.operand)
                    if isinstance(val, int):
                        if opcode == EVM.PUSH32:
                            if val in sha3_inv:
                                # restore precomputed hashes
                                ex.st.push(ex.sha3_data(con(sha3_inv[val])))
                            # TODO: support more commonly used concrete keccak values
                            elif val == EMPTY_KECCAK:
                                ex.st.push(ex.sha3_data(b""))
                            else:
                                ex.st.push(val)
                        else:
                            ex.st.push(val)
                    else:
                        ex.st.push(uint256(val) if opcode < EVM.PUSH32 else val)

                elif EVM.DUP1 <= opcode <= EVM.DUP16:
                    ex.st.dup(opcode - EVM.DUP1 + 1)

                elif EVM.SWAP1 <= opcode <= EVM.SWAP16:
                    ex.st.swap(opcode - EVM.SWAP1 + 1)

                else:
                    # TODO: switch to InvalidOpcode when we have full opcode coverage
                    # this halts the path, but we should only halt the current context
                    raise HalmosException(f"Unsupported opcode {hex(opcode)}")

                ex.advance_pc()
                stack.push(ex, step_id)

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
            balance=balance,
            #
            block=block,
            #
            context=context,
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
            sha3s={},
            storages={},
            balances={},
        )
