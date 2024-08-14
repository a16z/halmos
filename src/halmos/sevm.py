# SPDX-License-Identifier: AGPL-3.0

import math
import re

from copy import deepcopy
from collections import defaultdict
from dataclasses import dataclass, field
from functools import reduce
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
from z3 import *

from .bytevec import Chunk, ByteVec
from .cheatcodes import halmos_cheat_code, hevm_cheat_code, Prank
from .config import Config as HalmosConfig
from .console import console
from .exceptions import *
from .utils import *
from .warnings import (
    warn_code,
    LIBRARY_PLACEHOLDER,
    INTERNAL_ERROR,
)

Steps = Dict[int, Dict[str, Any]]  # execution tree

EMPTY_BYTES = ByteVec()
EMPTY_KECCAK = con(0xC5D2460186F7233C927E7DB2DCC703C0E500B653CA82273B7BFAD8045D85A470)
MAX_CALL_DEPTH = 1024

# TODO: make this configurable
MAX_MEMORY_SIZE = 2**20


# symbolic states
# calldataload(index)
f_calldataload = Function("f_calldataload", BitVecSort256, BitVecSort256)
# calldatasize()
f_calldatasize = Function("f_calldatasize", BitVecSort256)
# extcodesize(target address)
f_extcodesize = Function("f_extcodesize", BitVecSort160, BitVecSort256)
# extcodehash(target address)
f_extcodehash = Function("f_extcodehash", BitVecSort160, BitVecSort256)
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


class Instruction:
    opcode: int
    pc: int = -1
    next_pc: int = -1
    operand: Optional[ByteVec] = None

    def __init__(self, opcode, pc=-1, next_pc=-1, operand=None) -> None:
        self.opcode = opcode

        self.pc = pc
        self.next_pc = next_pc
        self.operand = operand

    def __str__(self) -> str:
        operand_str = f" {hexify(self.operand)}" if self.operand is not None else ""
        return f"{mnemonic(self.opcode)}{operand_str}"

    def __repr__(self) -> str:
        return f"Instruction({mnemonic(self.opcode)}, pc={self.pc}, operand={repr(self.operand)})"

    def __len__(self) -> int:
        return self.next_pc - self.pc


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
    topics: List[Word]
    data: Optional[Bytes]


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
    gas: Optional[Word] = None

    def is_create(self) -> bool:
        return self.call_scheme in (EVM.CREATE, EVM.CREATE2)


@dataclass
class CallOutput:
    """
    Data record produced during the execution of a call.
    """

    data: Optional[ByteVec] = None
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
            v = con(v)

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
        if loc > MAX_MEMORY_SIZE:
            raise OutOfGasError(f"MLOAD {loc} > MAX_MEMORY_SIZE")
        return loc

    def ret(self) -> ByteVec:
        loc: int = self.mloc()
        size: int = int_of(self.pop(), "symbolic return data size")  # size in bytes

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

    def __init__(self, code: Optional[ByteVec] = None) -> None:
        # if
        if not isinstance(code, ByteVec):
            code = ByteVec(code)

        self._code = code

        # maps pc to decoded instruction (including operand and next_pc)
        self._insn = dict()

    def __init_jumpdests(self):
        assert not hasattr(self, "_jumpdests")
        self._jumpdests = set((pc for (pc, op) in iter(self) if op == EVM.JUMPDEST))

    def __iter__(self):
        return CodeIterator(self)

    def from_hexcode(hexcode: str):
        """Create a contract from a hexcode string, e.g. "aabbccdd" """
        if not isinstance(hexcode, str):
            raise ValueError(hexcode)

        if len(hexcode) % 2 != 0:
            raise ValueError(hexcode)

        if "__" in hexcode:
            warn_code(
                LIBRARY_PLACEHOLDER, f"contract hexcode contains library placeholder"
            )

        try:
            bytecode = bytes.fromhex(stripped(hexcode))
            return Contract(ByteVec(bytecode))
        except ValueError as e:
            raise ValueError(f"{e} (hexcode={hexcode})")

    def _decode_instruction(self, pc: int) -> Instruction:
        opcode = int_of(self._code[pc], f"symbolic opcode at pc={pc}")

        if EVM.PUSH1 <= opcode <= EVM.PUSH32:
            operand_offset = pc + 1
            operand_size = opcode - EVM.PUSH0
            next_pc = operand_offset + operand_size

            # TODO: consider slicing lazily
            operand = self.slice(operand_offset, next_pc).unwrap()
            return Instruction(opcode, pc=pc, operand=operand, next_pc=next_pc)

        return Instruction(opcode, pc=pc, next_pc=pc + 1)

    def decode_instruction(self, pc: int) -> Instruction:
        insn = self._insn.get(pc, None)
        if insn is None:
            insn = self._decode_instruction(pc)
            self._insn[pc] = insn

        return insn

    def next_pc(self, pc):
        return self.decode_instruction(pc).next_pc

    def slice(self, start, stop) -> ByteVec:
        return self._code.slice(start, stop)

    def __getitem__(self, key: int) -> Byte:
        """Returns the byte at the given offset."""
        offset = int_of(key, "symbolic index into contract bytecode {offset!r}")
        return self._code.get_byte(offset)

    def __len__(self) -> int:
        """Returns the length of the bytecode in bytes."""
        return len(self._code)

    def valid_jump_destinations(self) -> set:
        """Returns the set of valid jump destinations."""
        if not hasattr(self, "_jumpdests"):
            self.__init_jumpdests()

        return self._jumpdests


class CodeIterator:
    def __init__(self, contract: Contract):
        self.contract = contract
        self.pc = 0

    def __iter__(self):
        return self

    def __next__(self) -> Tuple[int, int]:
        """Returns a tuple of (pc, opcode)"""
        if self.pc >= len(self.contract):
            raise StopIteration

        try:
            pc = self.pc
            insn = self.contract.decode_instruction(pc)
            self.pc = insn.next_pc
            return (pc, insn.opcode)
        except NotConcreteError:
            raise StopIteration


@dataclass(frozen=True)
class SMTQuery:
    smtlib: str
    assertions: List  # list of assertion ids


class Path:
    # a Path object represents a prefix of the path currently being executed
    # initially, it's an empty path at the beginning of execution

    solver: Solver
    num_scopes: int
    # path constraints include both explicit branching conditions and implicit assumptions (eg, no hash collisions)
    conditions: Dict  # cond -> bool (true if explicit branching conditions)
    pending: List

    def __init__(self, solver: Solver):
        self.solver = solver
        self.num_scopes = 0
        self.conditions = {}
        self.pending = []

    def __deepcopy__(self, memo):
        raise NotImplementedError(f"use the branch() method instead of deepcopy()")

    def __str__(self) -> str:
        return "".join(
            [
                f"- {cond}\n"
                for cond in self.conditions
                if self.conditions[cond] and str(cond) != "True"
            ]
        )

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
            tmp_solver = SolverFor("QF_AUFBV")
            for cond in self.conditions:
                tmp_solver.assert_and_track(cond, str(cond.get_id()))
            query = tmp_solver.to_smt2()
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
            warn_code(INTERNAL_ERROR, f"path.append(false)")

        if cond not in self.conditions:
            self.solver.add(cond)
            self.conditions[cond] = branching

    def extend(self, conds, branching=False):
        for cond in conds:
            self.append(cond, branching=branching)

    def extend_path(self, path):
        # branching conditions are not preserved
        self.extend(path.conditions.keys())


class Exec:  # an execution path
    # network
    code: Dict[Address, Contract]
    storage: Dict[Address, Dict[int, Any]]  # address -> { storage slot -> value }
    balance: Any  # address -> balance

    # block
    block: Block

    # tx
    context: CallContext
    callback: Optional[Callable]  # to be called when returning back to parent context

    # vm state
    pgm: Contract
    pc: int
    st: State  # stack and memory
    jumpis: Dict[str, Dict[bool, int]]  # for loop detection
    symbolic: bool  # symbolic or concrete storage
    addresses_to_delete: Set[Address]

    # path
    path: Path  # path conditions
    alias: Dict[Address, Address]  # address aliases

    # internal bookkeeping
    cnts: Dict[str, int]  # counters
    sha3s: Dict[Word, int]  # sha3 hashes generated
    storages: Dict[Any, Any]  # storage updates
    balances: Dict[Any, Any]  # balance updates
    calls: List[Any]  # external calls
    known_keys: Dict[Any, Any]  # maps address to private key
    known_sigs: Dict[Any, Any]  # maps (private_key, digest) to (v, r, s)

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
        self.symbolic = kwargs["symbolic"]
        self.addresses_to_delete = kwargs.get("addresses_to_delete") or set()
        #
        self.path = kwargs["path"]
        self.alias = kwargs["alias"]
        #
        self.cnts = kwargs["cnts"]
        self.sha3s = kwargs["sha3s"]
        self.storages = kwargs["storages"]
        self.balances = kwargs["balances"]
        self.calls = kwargs["calls"]
        self.known_keys = kwargs["known_keys"] if "known_keys" in kwargs else {}
        self.known_sigs = kwargs["known_sigs"] if "known_sigs" in kwargs else {}

        assert_address(self.origin())
        assert_address(self.caller())
        assert_address(self.this())

    def context_str(self) -> str:
        opcode = self.current_opcode()
        return f"addr={hexify(self.this())} pc={self.pc} insn={mnemonic(opcode)}"

    def halt(
        self,
        data: Optional[ByteVec],
        error: Optional[EvmException] = None,
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

    def current_opcode(self) -> UnionType[int, BitVecRef]:
        return unbox_int(self.pgm[self.pc])

    def current_instruction(self) -> Instruction:
        return self.pgm.decode_instruction(self.pc)

    def resolve_prank(self, to: Address) -> Tuple[Address, Address]:
        # this potentially "consumes" the active prank
        prank_result = self.context.prank.lookup(to)
        caller = self.this() if prank_result.sender is None else prank_result.sender
        origin = self.origin() if prank_result.origin is None else prank_result.origin
        return caller, origin

    def set_code(self, who: Address, code: UnionType[ByteVec, Contract]) -> None:
        """
        Sets the code at a given address.
        """
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
                    f"Balance: {self.balance}\n",
                    f"Storage:\n",
                    "".join(
                        map(
                            lambda x: f"- {x}: {self.storage[x]}\n",
                            self.storage,
                        )
                    ),
                    f"Path:\n{self.path}",
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
        cond = simplify(cond)

        if is_true(cond):
            return sat

        if is_false(cond):
            return unsat

        return self.path.check(cond)

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
        value = self.select(self.balance, uint160(addr), self.balances)
        # practical assumption on the max balance per account
        self.path.append(ULT(value, con(2**96)))
        return value

    def balance_update(self, addr: Word, value: Word) -> None:
        assert_address(addr)
        assert_uint256(value)
        new_balance_var = Array(
            f"balance_{1+len(self.balances):>02}", BitVecSort160, BitVecSort256
        )
        new_balance = Store(self.balance, addr, value)
        self.path.append(new_balance_var == new_balance)
        self.balance = new_balance_var
        self.balances[new_balance_var] = new_balance

    def sha3(self) -> None:
        loc: int = self.st.mloc()
        size: int = int_of(self.st.pop(), "symbolic SHA3 data size")
        data = self.st.memory.slice(loc, loc + size).unwrap() if size else b""
        sha3_image = self.sha3_data(data)
        self.st.push(sha3_image)

    def sha3_data(self, data: Bytes) -> Word:
        size = byte_length(data)

        if size > 0:
            if isinstance(data, bytes):
                data = bytes_to_bv_value(data)

            f_sha3 = Function(
                f"f_sha3_{size * 8}", BitVecSorts[size * 8], BitVecSort256
            )
            sha3_expr = f_sha3(data)
        else:
            sha3_expr = EMPTY_KECCAK

        # assume hash values are sufficiently smaller than the uint max
        self.path.append(ULE(sha3_expr, 2**256 - 2**64))

        # assume no hash collision
        self.assume_sha3_distinct(sha3_expr)

        # handle create2 hash
        if size == 85 and eq(extract_bytes(data, 0, 1), con(0xFF, size_bits=8)):
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
                self.path.append(
                    Implies(
                        sha3_expr.arg(0) != prev_sha3_expr.arg(0),
                        sha3_expr != prev_sha3_expr,
                    )
                )
            else:
                # inputs have different sizes: assume the outputs are different
                self.path.append(sha3_expr != prev_sha3_expr)

        self.path.append(sha3_expr != con(0))
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

    def returndata(self) -> Optional[ByteVec]:
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

    def jumpi_id(self) -> str:
        # TODO: avoid scanning the entire stack for jumpdests every time
        valid_jumpdests = self.pgm.valid_jump_destinations()

        jumpdests_str = (
            str(unboxed)
            for x in self.st.stack
            if (unboxed := unbox_int(x)) in valid_jumpdests
        )

        return f"{self.pc}:{','.join(jumpdests_str)}"

    # deploy libraries and resolve library placeholders in hexcode
    def resolve_libs(self, creation_hexcode, deployed_hexcode, lib_references) -> str:
        if lib_references:
            for lib in lib_references:
                address = self.new_address()

                self.code[address] = Contract.from_hexcode(
                    lib_references[lib]["hexcode"]
                )

                placeholder = lib_references[lib]["placeholder"]
                hex_address = stripped(hex(address.as_long())).zfill(40)

                creation_hexcode = creation_hexcode.replace(placeholder, hex_address)
                deployed_hexcode = deployed_hexcode.replace(placeholder, hex_address)

        return (creation_hexcode, deployed_hexcode)


class Storage:
    pass


class SolidityStorage(Storage):
    @classmethod
    def empty(cls, addr: BitVecRef, slot: int, keys: Tuple) -> ArrayRef:
        num_keys = len(keys)
        size_keys = cls.bitsize(keys)
        return Array(
            f"storage_{id_str(addr)}_{slot}_{num_keys}_{size_keys}_00",
            BitVecSorts[size_keys],
            BitVecSort256,
        )

    @classmethod
    def init(cls, ex: Exec, addr: Any, slot: int, keys: Tuple) -> None:
        assert_address(addr)
        num_keys = len(keys)
        size_keys = cls.bitsize(keys)
        if slot not in ex.storage[addr]:
            ex.storage[addr][slot] = {}
        if num_keys not in ex.storage[addr][slot]:
            ex.storage[addr][slot][num_keys] = {}
        if size_keys not in ex.storage[addr][slot][num_keys]:
            if size_keys == 0:
                if ex.symbolic:
                    label = f"storage_{id_str(addr)}_{slot}_{num_keys}_{size_keys}_00"
                    ex.storage[addr][slot][num_keys][size_keys] = BitVec(
                        label, BitVecSort256
                    )
                else:
                    ex.storage[addr][slot][num_keys][size_keys] = con(0)
            else:
                # do not use z3 const array `K(BitVecSort(size_keys), con(0))` when not ex.symbolic
                # instead use normal smt array, and generate emptyness axiom; see load()
                ex.storage[addr][slot][num_keys][size_keys] = cls.empty(
                    addr, slot, keys
                )

    @classmethod
    def load(cls, ex: Exec, addr: Any, loc: Word) -> Word:
        offsets = cls.decode(loc)
        if not len(offsets) > 0:
            raise ValueError(offsets)
        slot, keys = int_of(offsets[0], "symbolic storage base slot"), offsets[1:]
        cls.init(ex, addr, slot, keys)
        num_keys = len(keys)
        size_keys = cls.bitsize(keys)
        if num_keys == 0:
            return ex.storage[addr][slot][num_keys][size_keys]
        else:
            if not ex.symbolic:
                # generate emptyness axiom for each array index, instead of using quantified formula; see init()
                ex.path.append(
                    Select(cls.empty(addr, slot, keys), concat(keys)) == con(0)
                )
            return ex.select(
                ex.storage[addr][slot][num_keys][size_keys], concat(keys), ex.storages
            )

    @classmethod
    def store(cls, ex: Exec, addr: Any, loc: Any, val: Any) -> None:
        offsets = cls.decode(loc)
        if not len(offsets) > 0:
            raise ValueError(offsets)
        slot, keys = int_of(offsets[0], "symbolic storage base slot"), offsets[1:]
        cls.init(ex, addr, slot, keys)
        num_keys = len(keys)
        size_keys = cls.bitsize(keys)
        if num_keys == 0:
            ex.storage[addr][slot][num_keys][size_keys] = val
        else:
            new_storage_var = Array(
                f"storage_{id_str(addr)}_{slot}_{num_keys}_{size_keys}_{1+len(ex.storages):>02}",
                BitVecSorts[size_keys],
                BitVecSort256,
            )
            new_storage = Store(
                ex.storage[addr][slot][num_keys][size_keys], concat(keys), val
            )
            ex.path.append(new_storage_var == new_storage)
            ex.storage[addr][slot][num_keys][size_keys] = new_storage_var
            ex.storages[new_storage_var] = new_storage

    @classmethod
    def decode(cls, loc: Any) -> Any:
        loc = normalize(loc)
        # m[k] : hash(k.m)
        if loc.decl().name() == "f_sha3_512":
            args = loc.arg(0)
            offset = simplify(Extract(511, 256, args))
            base = simplify(Extract(255, 0, args))
            return cls.decode(base) + (offset, con(0))
        # a[i] : hash(a) + i
        elif loc.decl().name() == "f_sha3_256":
            base = loc.arg(0)
            return cls.decode(base) + (con(0),)
        # m[k] : hash(k.m)  where |k| != 256-bit
        elif loc.decl().name().startswith("f_sha3_"):
            sha3_input = normalize(loc.arg(0))
            if sha3_input.decl().name() == "concat" and sha3_input.num_args() == 2:
                offset = simplify(sha3_input.arg(0))
                base = simplify(sha3_input.arg(1))
                if offset.size() != 256 and base.size() == 256:
                    return cls.decode(base) + (offset, con(0))
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
    def bitsize(cls, keys: Tuple) -> int:
        size = sum([key.size() for key in keys])
        if len(keys) > 0 and size == 0:
            raise ValueError(keys)
        return size


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
            ex.path.append(Select(cls.empty(addr, loc), loc) == con(0))
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
        ex.path.append(new_storage_var == new_storage)
        ex.storage[addr][loc.size()] = new_storage_var
        ex.storages[new_storage_var] = new_storage

    @classmethod
    def decode(cls, loc: Any) -> Any:
        loc = normalize(loc)
        if loc.decl().name() == "f_sha3_512":  # hash(hi,lo), recursively
            args = loc.arg(0)
            hi = cls.decode(simplify(Extract(511, 256, args)))
            lo = cls.decode(simplify(Extract(255, 0, args)))
            return cls.simple_hash(Concat(hi, lo))
        elif loc.decl().name().startswith("f_sha3_"):
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
    def add_all(cls, args: List) -> BitVecRef:
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


@dataclass
class WorklistItem:
    ex: Exec
    step: int


class Worklist:
    def __init__(self):
        self.stack = []

    def push(self, ex: Exec, step: int):
        self.stack.append(WorklistItem(ex, step))

    def pop(self) -> WorklistItem:
        return self.stack.pop()

    def __len__(self) -> int:
        return len(self.stack)


class SEVM:
    options: HalmosConfig
    storage_model: Type[SomeStorage]
    logs: HalmosLogs
    steps: Steps

    def __init__(self, options: HalmosConfig) -> None:
        self.options = options
        self.logs = HalmosLogs()
        self.steps: Steps = {}

        # init unknown calls
        hex_string = options.uninterpreted_unknown_calls.strip()
        self.unknown_calls: List[int] = [int(x, 16) for x in hex_string.split(",") if x]

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
        # ex.path.append(Or(y == con(0), ULT(term, y))) # (x % y) < y if y != 0
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
                    return con(1)

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

        # set new timeout temporarily for this task
        ex.path.solver.set(timeout=max(1000, self.options.solver_timeout_branching))

        if target not in ex.alias:
            for addr in ex.code:
                if ex.check(target != addr) == unsat:  # target == addr
                    if self.options.debug:
                        debug(f"Address alias: {hexify(addr)} for {hexify(target)}")
                    ex.alias[target] = addr
                    ex.path.append(target == addr)
                    break

        # reset timeout
        ex.path.solver.set(timeout=self.options.solver_timeout_branching)

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
        if is_false(balance_cond):
            raise InfeasiblePath("transfer_value: balance is not enough")
        ex.path.append(balance_cond)

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

        pranked_caller, pranked_origin = ex.resolve_prank(to)
        arg = ex.st.memory.slice(arg_loc, arg_loc + arg_size)

        def send_callvalue(condition=None) -> None:
            # no balance update for CALLCODE which transfers to itself
            if op == EVM.CALL:
                # TODO: revert if context is static
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
                    yield new_ex
                    return

                # restore vm state
                new_ex.pgm = ex.pgm
                new_ex.pc = ex.pc
                new_ex.st = deepcopy(ex.st)
                new_ex.jumpis = deepcopy(ex.jumpis)
                new_ex.symbolic = ex.symbolic

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
                new_ex.st.push(con(1) if subcall_success else con(0))

                if not subcall_success:
                    # revert network states
                    new_ex.code = orig_code.copy()
                    new_ex.storage = deepcopy(orig_storage)
                    new_ex.balance = orig_balance

                # add to worklist even if it reverted during the external call
                new_ex.next_pc()
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
                symbolic=ex.symbolic,
                #
                path=ex.path,
                alias=ex.alias,
                #
                cnts=ex.cnts,
                sha3s=ex.sha3s,
                storages=ex.storages,
                balances=ex.balances,
                calls=ex.calls,
                known_keys=ex.known_keys,
                known_sigs=ex.known_sigs,
            )

            stack.push(sub_ex, step_id)

        def call_unknown() -> None:
            call_id = len(ex.calls)

            if arg_size > 0:
                f_call = Function(
                    "f_call_" + str(arg_size * 8),
                    BitVecSort256,  # cnt
                    BitVecSort256,  # gas
                    BitVecSort160,  # to
                    BitVecSort256,  # value
                    BitVecSorts[arg_size * 8],  # args
                    BitVecSort256,
                )

                unwrapped = arg.unwrap()
                arg_bv = unwrapped if is_bv(unwrapped) else bytes_to_bv_value(unwrapped)

                exit_code = f_call(con(call_id), gas, to, fund, arg_bv)
            else:
                f_call = Function(
                    "f_call_" + str(arg_size * 8),
                    BitVecSort256,  # cnt
                    BitVecSort256,  # gas
                    BitVecSort160,  # to
                    BitVecSort256,  # value
                    BitVecSort256,
                )
                exit_code = f_call(con(call_id), gas, to, fund)
            exit_code_var = BitVec(f"call_exit_code_{call_id:>02}", BitVecSort256)

            if ret_size > 0:
                # actual return data will be capped or zero-padded by ret_size
                # FIX: this doesn't capture the case of returndatasize != ret_size
                actual_ret_size = ret_size
            else:
                actual_ret_size = self.options.return_size_of_unknown_calls

            ret = ByteVec()
            if actual_ret_size > 0:
                f_ret = Function(
                    "f_ret_" + str(actual_ret_size * 8),
                    BitVecSort256,
                    BitVecSorts[actual_ret_size * 8],
                )
                ret.append(f_ret(exit_code_var))

            # TODO: cover other precompiled

            # ecrecover
            if eq(to, con_addr(1)):
                # TODO: explicitly return empty data in case of an error
                # TODO: validate input and fork on error?
                # - v in [27, 28]
                # - r, s in [1, secp256k1n)

                # call never fails, errors result in empty returndata
                exit_code = con(1)

                digest = extract_bytes(arg, 0, 32)
                v = uint8(extract_bytes(arg, 32, 32))
                r = extract_bytes(arg, 64, 32)
                s = extract_bytes(arg, 96, 32)

                ret = ByteVec(uint256(f_ecrecover(digest, v, r, s)))

            # identity
            elif eq(to, con_addr(4)):
                exit_code = con(1)
                ret = arg

            # halmos cheat code
            elif eq(to, halmos_cheat_code.address):
                exit_code = con(1)
                ret = halmos_cheat_code.handle(ex, arg)

            # vm cheat code
            elif eq(to, hevm_cheat_code.address):
                exit_code = con(1)
                ret = hevm_cheat_code.handle(self, ex, arg, stack, step_id)

            # console
            elif eq(to, console.address):
                exit_code = con(1)
                console.handle(ex, arg)
                ret = ByteVec()

            # push exit code
            ex.path.append(exit_code_var == exit_code)
            ex.st.push(exit_code if is_bv_value(exit_code) else exit_code_var)

            # transfer msg.value
            send_callvalue(exit_code_var != con(0))

            # store return value
            if ret_size > 0:
                end_loc = ret_loc + ret_size
                if end_loc > MAX_MEMORY_SIZE:
                    raise HalmosException("returned data exceeds MAX_MEMORY_SIZE")

                ex.st.memory.set_slice(ret_loc, end_loc, ret)

            if not isinstance(ret, ByteVec):
                raise HalmosException(f"Invalid return value: {ret}")

            ex.context.trace.append(
                CallContext(
                    message=Message(
                        target=to,
                        caller=pranked_caller,
                        origin=pranked_origin,
                        value=fund,
                        data=ex.st.memory.slice(arg_loc, arg_loc + arg_size),
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
            stack.push(ex, step_id)

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
        if funsig in self.unknown_calls:
            self.logs.add_uninterpreted_unknown_call(funsig, to, arg)
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
    ) -> None:
        if ex.message().is_static:
            raise WriteInStaticContext(ex.context_str())

        value: Word = ex.st.pop()
        loc: int = int_of(ex.st.pop(), "symbolic CREATE offset")
        size: int = int_of(ex.st.pop(), "symbolic CREATE size")

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
            ex.next_pc()

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
        ex.code[new_addr] = Contract(b"")  # existing code must be empty
        ex.storage[new_addr] = {}  # existing storage may not be empty and reset here

        # transfer value
        self.transfer_value(ex, pranked_caller, new_addr, value)

        def callback(new_ex, stack, step_id):
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
            new_ex.symbolic = ex.symbolic

            if subcall.is_stuck():
                # internal errors abort the current path,
                yield new_ex
                return

            elif subcall.output.error is None:
                # new contract code, will revert if data is None
                new_ex.code[new_addr] = Contract(subcall.output.data)

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
            new_ex.next_pc()
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
            symbolic=False,
            #
            path=ex.path,
            alias=ex.alias,
            #
            cnts=ex.cnts,
            sha3s=ex.sha3s,
            storages=ex.storages,
            balances=ex.balances,
            calls=ex.calls,
            known_keys=ex.known_keys,
            known_sigs=ex.known_sigs,
        )

        stack.push(sub_ex, step_id)

    def jumpi(
        self,
        ex: Exec,
        stack: List[Tuple[Exec, int]],
        step_id: int,
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
            follow_true = visited[True] < self.options.loop
            follow_false = visited[False] < self.options.loop
            if not (follow_true and follow_false):
                self.logs.bounded_loops.append(jid)
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
            new_ex_false.next_pc()

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

    def jump(self, ex: Exec, stack: List[Tuple[Exec, int]], step_id: int) -> None:
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
            symbolic=ex.symbolic,
            #
            path=new_path,
            alias=ex.alias.copy(),
            #
            cnts=deepcopy(ex.cnts),
            sha3s=ex.sha3s.copy(),
            storages=ex.storages.copy(),
            balances=ex.balances.copy(),
            calls=ex.calls.copy(),
            known_keys=ex.known_keys,  # pass by reference, not need to copy
            known_sigs=ex.known_sigs,  # pass by reference, not need to copy
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

    def run(self, ex0: Exec) -> Iterator[Exec]:
        step_id: int = 0
        stack: Worklist = Worklist()
        stack.push(ex0, 0)

        def finalize(ex: Exec):
            # if it's at the top-level, there is no callback; yield the current execution state
            if ex.callback is None:
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
                        ex.halt(data=ex.st.ret(), error=Revert())
                    elif opcode == EVM.RETURN:
                        ex.halt(data=ex.st.ret())
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
                    offset: int = int_of(ex.st.pop(), "symbolic CALLDATALOAD offset")
                    ex.st.push(ex.calldata().get_word(offset))

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

                # TODO: define f_extcodesize for known addresses in advance
                elif opcode == EVM.EXTCODESIZE:
                    account = uint160(ex.st.pop())
                    account_addr = self.resolve_address_alias(ex, account)
                    if account_addr is not None:
                        codesize = len(ex.code[account_addr])
                    else:
                        codesize = f_extcodesize(account)
                        if (
                            eq(account, hevm_cheat_code.address)
                            or eq(account, halmos_cheat_code.address)
                            or eq(account, console.address)
                        ):
                            ex.path.append(codesize > 0)
                    ex.st.push(codesize)

                elif opcode == EVM.EXTCODECOPY:
                    account: Address = uint160(ex.st.pop())
                    loc: int = int_of(ex.st.pop(), "symbolic EXTCODECOPY offset")
                    offset: int = int_of(ex.st.pop(), "symbolic EXTCODECOPY offset")
                    size: int = int_of(ex.st.pop(), "symbolic EXTCODECOPY size")

                    if size > 0:
                        end_loc = loc + size
                        if end_loc > MAX_MEMORY_SIZE:
                            raise HalmosException("EXTCODECOPY > MAX_MEMORY_SIZE")

                        # TODO: handle the case where account may alias multiple addresses
                        account_addr = self.resolve_address_alias(ex, account)
                        if account_addr is None:
                            # this could be unsound if the solver in resolve_address_alias
                            # returns unknown, meaning that there is in fact a must-alias
                            # address, but we didn't find it in time
                            warn(
                                f"EXTCODECOPY: unknown address {hexify(account)} "
                                "is assumed to have empty bytecode"
                            )

                        account_code: Contract = ex.code.get(account_addr) or ByteVec()
                        codeslice: ByteVec = account_code._code.slice(
                            offset, offset + size
                        )
                        ex.st.memory.set_slice(loc, end_loc, codeslice)

                elif opcode == EVM.EXTCODEHASH:
                    account_addr = uint160(ex.st.pop())
                    alias_addr = self.resolve_address_alias(ex, account_addr)
                    addr = alias_addr if alias_addr is not None else account_addr

                    account_code: Optional[Contract] = ex.code.get(addr, None)

                    codehash = (
                        f_extcodehash(addr)
                        if account_code is None
                        else ex.sha3_data(account_code._code.unwrap())
                    )

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
                    self.call(ex, opcode, stack, step_id)
                    continue

                elif opcode == EVM.SHA3:
                    ex.sha3()

                elif opcode in [EVM.CREATE, EVM.CREATE2]:
                    self.create(ex, opcode, stack, step_id)
                    continue

                elif opcode == EVM.POP:
                    ex.st.pop()

                elif opcode == EVM.MLOAD:
                    loc: int = ex.st.mloc()
                    ex.st.push(ex.st.memory.get_word(loc))

                elif opcode == EVM.MSTORE:
                    loc: int = ex.st.mloc()
                    val: Word = ex.st.pop()
                    ex.st.memory.set_word(loc, uint256(val))

                elif opcode == EVM.MSTORE8:
                    loc: int = ex.st.mloc()
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
                    loc: int = ex.st.mloc()
                    offset: int = int_of(ex.st.pop(), "symbolic RETURNDATACOPY offset")
                    size: int = int_of(ex.st.pop(), "symbolic RETURNDATACOPY size")
                    end_loc = loc + size

                    if end_loc > MAX_MEMORY_SIZE:
                        raise HalmosException("RETURNDATACOPY > MAX_MEMORY_SIZE")

                    if size > 0:
                        if offset + size > ex.returndatasize():
                            raise OutOfBoundsRead("RETURNDATACOPY out of bounds")

                        data: ByteVec = ex.returndata().slice(offset, offset + size)
                        ex.st.memory.set_slice(loc, end_loc, data)

                elif opcode == EVM.CALLDATACOPY:
                    loc: int = ex.st.mloc()
                    offset: int = int_of(ex.st.pop(), "symbolic CALLDATACOPY offset")
                    size: int = int_of(ex.st.pop(), "symbolic CALLDATACOPY size")
                    end_loc = loc + size

                    if end_loc > MAX_MEMORY_SIZE:
                        raise HalmosException("CALLDATACOPY > MAX_MEMORY_SIZE")

                    if size > 0:
                        data: ByteVec = ex.calldata().slice(offset, offset + size)
                        ex.st.memory.set_slice(loc, end_loc, data)

                elif opcode == EVM.CODECOPY:
                    loc: int = ex.st.mloc()
                    offset: int = int_of(ex.st.pop(), "symbolic CODECOPY offset")
                    size: int = int_of(ex.st.pop(), "symbolic CODECOPY size")
                    end_loc = loc + size

                    if end_loc > MAX_MEMORY_SIZE:
                        raise HalmosException("CODECOPY > MAX_MEMORY_SIZE")

                    if size > 0:
                        codeslice: ByteVec = ex.pgm.slice(offset, offset + size)
                        ex.st.memory.set_slice(loc, loc + size, codeslice)

                elif opcode == EVM.MCOPY:
                    dest_offset = int_of(ex.st.pop(), "symbolic MCOPY destOffset")
                    src_offset = int_of(ex.st.pop(), "symbolic MCOPY srcOffset")
                    size = int_of(ex.st.pop(), "symbolic MCOPY size")

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
                        if self.options.debug:
                            warn(
                                f"Warning: the use of symbolic BYTE indexing may potentially "
                                f"impact the performance of symbolic reasoning: BYTE {idx} {w}"
                            )
                        ex.st.push(self.sym_byte_of(idx, w))

                elif EVM.LOG0 <= opcode <= EVM.LOG4:
                    if ex.message().is_static:
                        raise WriteInStaticContext(ex.context_str())

                    num_topics: int = opcode - EVM.LOG0
                    loc: int = ex.st.mloc()
                    size: int = int_of(ex.st.pop(), "symbolic LOG data size")
                    topics = list(ex.st.pop() for _ in range(num_topics))
                    data = ex.st.memory.slice(loc, loc + size)
                    ex.emit_log(EventLog(ex.this(), topics, data))

                elif opcode == EVM.PUSH0:
                    ex.st.push(con(0))

                elif EVM.PUSH1 <= opcode <= EVM.PUSH32:
                    if is_concrete(insn.operand):
                        val = int_of(insn.operand)
                        if opcode == EVM.PUSH32 and val in sha3_inv:
                            # restore precomputed hashes
                            ex.st.push(ex.sha3_data(con(sha3_inv[val])))
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
                stack.push(ex, step_id)

            except InfeasiblePath as err:
                # ignore infeasible path
                continue

            except EvmException as err:
                ex.halt(data=ByteVec(), error=err)
                yield from finalize(ex)
                continue

            except HalmosException as err:
                if self.options.debug:
                    print(err)

                ex.halt(data=None, error=err)
                yield from finalize(ex)
                continue

            except FailCheatcode as err:
                if not ex.is_halted():
                    # return data shouldn't be None, as it is considered being stuck
                    ex.halt(data=ByteVec(), error=err)
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
        symbolic,
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
            symbolic=symbolic,
            #
            path=path,
            alias={},
            #
            log=[],
            cnts=defaultdict(int),
            sha3s={},
            storages={},
            balances={},
            calls=[],
        )
