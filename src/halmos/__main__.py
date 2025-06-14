# SPDX-License-Identifier: AGPL-3.0

import faulthandler
import gc
import json
import logging
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
import traceback
from collections import Counter, defaultdict
from collections.abc import Iterable, Iterator
from concurrent.futures import Future
from dataclasses import asdict, dataclass
from datetime import timedelta
from enum import Enum
from functools import partial
from importlib import metadata
from types import MappingProxyType

from rich.console import Group
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree
from z3 import (
    BitVec,
    BoolRef,
    Solver,
    ZeroExt,
    eq,
    set_option,
    unsat,
)

import halmos.traces
from halmos.build import (
    build_output_iterator,
    import_libs,
    parse_build_out,
    parse_devdoc,
    parse_natspec,
)
from halmos.bytevec import ByteVec
from halmos.calldata import FunctionInfo, get_abi, mk_calldata
from halmos.cheatcodes import snapshot_state
from halmos.config import Config as HalmosConfig
from halmos.config import (
    ConfigSource,
    arg_parser,
    default_config,
    resolve_config_files,
    toml_parser,
)
from halmos.constants import (
    VERBOSITY_TRACE_CONSTRUCTOR,
    VERBOSITY_TRACE_COUNTEREXAMPLE,
    VERBOSITY_TRACE_PATHS,
    VERBOSITY_TRACE_SETUP,
)
from halmos.contract import CoverageReporter
from halmos.env import init_env
from halmos.exceptions import FailCheatcode, HalmosException
from halmos.flamegraphs import CallSequenceFlamegraph, call_flamegraph, exec_flamegraph
from halmos.logs import (
    COUNTEREXAMPLE_INVALID,
    INTERNAL_ERROR,
    LOOP_BOUND,
    REVERT_ALL,
    debug,
    error,
    logger,
    logger_unique,
    warn,
    warn_code,
)
from halmos.mapper import BuildOut, DeployAddressMapper
from halmos.processes import ExecutorRegistry, ShutdownError
from halmos.sevm import (
    EMPTY_BALANCE,
    FOUNDRY_CALLER,
    FOUNDRY_ORIGIN,
    FOUNDRY_TEST,
    ONE,
    SEVM,
    ZERO,
    Block,
    CallContext,
    Contract,
    Exec,
    Message,
    Path,
    Profiler,
    SMTQuery,
    id_str,
    jumpid_str,
    mnemonic,
)
from halmos.solve import (
    ContractContext,
    FunctionContext,
    InvariantTestingContext,
    PathContext,
    SolverOutput,
    solve_end_to_end,
    solve_low_level,
)
from halmos.traces import (
    render_trace,
    rendered_address,
    rendered_call_sequence,
    rendered_trace,
)
from halmos.ui import suspend_status, ui
from halmos.utils import (
    EVM,
    Address,
    BitVecSort256,
    Bytes,
    NamedTimer,
    Word,
    address,
    color_error,
    con,
    con_addr,
    create_solver,
    cyan,
    extract_bytes,
    green,
    hexify,
    indent_text,
    int_of,
    red,
    smt_and,
    smt_or,
    uid,
    unbox_int,
    yellow,
)

faulthandler.enable()


# Python version >=3.8.14, >=3.9.14, >=3.10.7, or >=3.11
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(0)

# we need to be able to process at least the max message depth (1024)
sys.setrecursionlimit(1024 * 4)

# sometimes defaults to cp1252 on Windows, which can cause UnicodeEncodeError
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")


@dataclass(frozen=True)
class TestResult:
    name: str  # test function name (funsig)
    exitcode: int
    num_models: int = None
    models: list[SolverOutput] = None
    num_paths: tuple[int, int, int] = None  # number of paths: [total, success, blocked]
    time: tuple[int, int, int] = None  # time: [total, paths, models]
    num_bounded_loops: int = None  # number of incomplete loops


class Exitcode(Enum):
    PASS = 0
    COUNTEREXAMPLE = 1
    TIMEOUT = 2
    STUCK = 3
    REVERT_ALL = 4
    EXCEPTION = 5


PASS = Exitcode.PASS.value
COUNTEREXAMPLE = Exitcode.COUNTEREXAMPLE.value


def with_devdoc(args: HalmosConfig, fn_sig: str, contract_json: dict) -> HalmosConfig:
    devdoc = parse_devdoc(fn_sig, contract_json)
    if not devdoc:
        return args

    overrides = arg_parser().parse_args(shlex.split(devdoc))
    source = ConfigSource.function_annotation
    return args.with_overrides(source, **vars(overrides))


def with_natspec(
    args: HalmosConfig, contract_name: str, contract_natspec: str
) -> HalmosConfig:
    if not contract_natspec:
        return args

    parsed = parse_natspec(contract_natspec)
    if not parsed:
        return args

    overrides = arg_parser().parse_args(shlex.split(parsed))
    source = ConfigSource.contract_annotation
    return args.with_overrides(source, **vars(overrides))


def load_config(_args) -> HalmosConfig:
    config = default_config()

    # parse CLI args first, so that can get `--help` out of the way and resolve `--debug`
    # but don't apply the CLI overrides yet
    cli_overrides = arg_parser().parse_args(_args)

    # then for each config file, parse it and override the args
    config_files = resolve_config_files(_args)
    for config_file in config_files:
        if not os.path.exists(config_file):
            error(f"Config file not found: {config_file}")
            sys.exit(2)

        overrides = toml_parser().parse_file(config_file)
        config_file = ConfigSource.config_file
        config = config.with_overrides(config_file, **overrides)

    # finally apply the CLI overrides
    command_line = ConfigSource.command_line
    config = config.with_overrides(command_line, **vars(cli_overrides))

    return config


def mk_block() -> Block:
    # foundry default values
    block = Block(
        basefee=ZERO,
        chainid=con(31337),
        coinbase=address(0),
        difficulty=ZERO,
        gaslimit=con(2**63 - 1),
        number=ONE,
        timestamp=ONE,
    )
    return block


def mk_addr(name: str) -> Address:
    return BitVec(name, 160)


def mk_solver(args: HalmosConfig, logic="QF_AUFBV", ctx=None) -> Solver:
    # in the config, we have a float in seconds
    # z3 expects an int in milliseconds
    timeout_ms = int(args.solver_timeout_branching * 1000)

    return create_solver(
        logic=logic,
        ctx=ctx,
        timeout=timeout_ms,
        max_memory=args.solver_max_memory,
    )


def deploy_test(ctx: FunctionContext, sevm: SEVM) -> Exec:
    args = ctx.args

    message = Message(
        target=FOUNDRY_TEST,
        caller=FOUNDRY_CALLER,
        origin=FOUNDRY_ORIGIN,
        value=0,
        data=ByteVec(),
        call_scheme=EVM.CREATE,
    )

    this = FOUNDRY_TEST

    ex = sevm.mk_exec(
        code={this: Contract(b"")},
        storage={this: sevm.mk_storagedata()},
        transient_storage={this: sevm.mk_storagedata()},
        balance=EMPTY_BALANCE,
        block=mk_block(),
        context=CallContext(message=message),
        pgm=None,  # to be added
        path=Path(ctx.solver),
    )

    # foundry default balance for the test contract
    ex.balance_update(this, con(0xFFFFFFFFFFFFFFFFFFFFFFFF))

    # deploy libraries and resolve library placeholders in hexcode
    contract_ctx = ctx.contract_ctx
    (creation_hexcode, _) = ex.resolve_libs(
        contract_ctx.creation_hexcode, contract_ctx.deployed_hexcode, contract_ctx.libs
    )

    # test contract creation bytecode
    creation_bytecode = Contract.from_hexcode(creation_hexcode)
    ex.pgm = creation_bytecode

    # create test contract
    exs = list(sevm.run(ex))

    # sanity check
    if len(exs) != 1:
        raise HalmosException(f"constructor: # of paths: {len(exs)}")

    [ex] = exs

    if args.flamegraph:
        exec_flamegraph.add(ex.context)

    if args.verbose >= VERBOSITY_TRACE_CONSTRUCTOR:
        print("Constructor trace:")
        render_trace(ex.context)

    output = ex.context.output
    returndata = output.data
    if output.error is not None or not returndata:
        raise HalmosException(f"constructor failed: {output.error=} {returndata=}")

    deployed_bytecode = Contract(returndata)
    ex.try_resolve_contract_info(deployed_bytecode, args.coverage_output)
    ex.set_code(this, deployed_bytecode)
    ex.pgm = deployed_bytecode

    # reset vm state
    ex.reset()

    return ex


def setup(ctx: FunctionContext) -> Exec:
    setup_timer = NamedTimer("setup")
    setup_timer.create_subtimer("decode")

    args, setup_info = ctx.args, ctx.info
    sevm = SEVM(args, setup_info)
    setup_ex = deploy_test(ctx, sevm)

    setup_timer.create_subtimer("run")

    setup_sig = setup_info.sig
    if not setup_sig:
        if args.statistics:
            print(setup_timer.report())
        return setup_ex

    # TODO: dyn_params may need to be passed to mk_calldata in run()
    calldata, dyn_params = mk_calldata(ctx.contract_ctx.abi, setup_info, args)
    setup_ex.path.process_dyn_params(dyn_params)

    setup_ex.context = CallContext(
        message=Message(
            target=FOUNDRY_TEST,
            caller=FOUNDRY_CALLER,
            origin=FOUNDRY_ORIGIN,
            value=0,
            data=calldata,
            call_scheme=EVM.CALL,
        ),
    )

    setup_exs_all = sevm.run(setup_ex)
    setup_exs_no_error: list[tuple[Exec, SMTQuery]] = []
    flamegraph_enabled = args.flamegraph

    for path_id, setup_ex in enumerate(setup_exs_all):
        if args.verbose >= VERBOSITY_TRACE_SETUP:
            print(f"{setup_sig} trace #{path_id}:")
            render_trace(setup_ex.context)

        if flamegraph_enabled:
            exec_flamegraph.add(setup_ex.context)

        if err := setup_ex.context.output.error:
            opcode = setup_ex.current_opcode()
            if opcode not in [EVM.REVERT, EVM.INVALID]:
                warn_code(
                    INTERNAL_ERROR,
                    f"in {setup_sig}, executing {mnemonic(opcode)} failed with: {err}",
                )

            # only render the trace if we didn't already do it
            if VERBOSITY_TRACE_COUNTEREXAMPLE <= args.verbose < VERBOSITY_TRACE_SETUP:
                print(f"{setup_sig} trace:")
                render_trace(setup_ex.context)

        else:
            # note: ex.path.to_smt2() needs to be called at this point. The solver object is shared across paths,
            # and solver.to_smt2() will return a different query if it is called after a different path is explored.
            setup_exs_no_error.append((setup_ex, setup_ex.path.to_smt2(args)))

    setup_exs: list[Exec] = []

    match setup_exs_no_error:
        case []:
            pass
        case [(ex, _)]:
            setup_exs.append(ex)
        case _:
            for path_id, (ex, query) in enumerate(setup_exs_no_error):
                path_ctx = PathContext(
                    args=args,
                    path_id=path_id,
                    query=query,
                    solving_ctx=ctx.solving_ctx,
                )
                solver_output = solve_low_level(path_ctx)
                if solver_output.result != unsat:
                    setup_exs.append(ex)
                    if len(setup_exs) > 1:
                        break

    match len(setup_exs):
        case 0:
            raise HalmosException(f"No successful path found in {setup_sig}")
        case n if n > 1:
            debug("\n".join(map(str, setup_exs)))
            raise HalmosException(f"Multiple paths were found in {setup_sig}")

    [setup_ex] = setup_exs

    if args.print_setup_states:
        print(setup_ex)

    if sevm.logs.bounded_loops:
        warn_code(
            LOOP_BOUND,
            f"{setup_sig}: paths have not been fully explored due to the loop unrolling bound: {args.loop}",
        )
        debug("\n".join(jumpid_str(x) for x in sevm.logs.bounded_loops))

    if args.statistics:
        print(setup_timer.report())

    return setup_ex


def is_global_fail_set(context: CallContext) -> bool:
    hevm_fail = isinstance(context.output.error, FailCheatcode)
    return hevm_fail or any(is_global_fail_set(x) for x in context.subcalls())


def get_state_id(ex: Exec) -> bytes:
    """
    Computes the state snapshot hash, incorporating constraints on state variables.

    Assumes constraints on state variables have been precomputed by running Exec.path_slice() after completing a transaction.
    Do not use this during transaction execution.
    """
    return snapshot_state(ex, include_path=True).unwrap()


def run_target_function(
    args: HalmosConfig,
    ex: Exec,
    addr: Address,
    abi: dict,
    fun_info: FunctionInfo,
    tx_origin: Address,
    msg_sender: Address,
    msg_value: Word,
    msg_sender_cond: BoolRef | None = None,
) -> Iterator[Exec]:
    try:
        # initialize symbolic execution environment
        sevm = SEVM(args, fun_info)
        solver = mk_solver(args)
        path = Path(solver)
        path.extend_path(ex.path)

        # prepare calldata and dynamic parameters
        calldata, dyn_params = mk_calldata(
            abi, fun_info, args, new_symbol_id=ex.new_symbol_id
        )
        path.process_dyn_params(dyn_params)

        # add (optional) constraints on msg_sender
        if msg_sender_cond is not None:
            path.append(msg_sender_cond)

        # construct the transaction message
        message = Message(
            target=addr,
            caller=msg_sender,
            origin=tx_origin,
            value=msg_value,
            data=calldata,
            call_scheme=EVM.CALL,
            fun_info=fun_info,
        )

        # execute the transaction and yield output states
        yield from sevm.run_message(ex, message, path)

    finally:
        reset(solver)


def run_target_contract(
    ctx: ContractContext, ex: Exec, addr: Address
) -> Iterator[Exec]:
    """
    Executes a given contract from a given input state and yields all output states.

    Args:
        ctx: The context of the test contract, which differs from the target contract to be executed.
        ex: The input state.
        addr: The address of the contract to be executed.

    Returns:
        A generator of output states.

    Raises:
        ValueError: If the contract name cannot be found for the given address.
    """
    args = ctx.args
    inv_ctx = ctx.inv_ctx
    excluded_senders = inv_ctx.excluded_senders
    # TODO: implement memoization
    effective_target_senders = inv_ctx.target_senders - excluded_senders

    # retrieve the contract name and metadata from the given address
    code = ex.code[addr]
    contract_name = code.contract_name
    filename = code.filename

    if not contract_name:
        raise ValueError(f"couldn't find the contract name for: {addr}")

    contract_json = BuildOut().get_by_name(contract_name, filename)
    abi = get_abi(contract_json)

    # iterate over each function in the target contract
    target_selectors = resolve_target_selectors(ctx.inv_ctx, addr, contract_json)
    for fun_sig, fun_selector in target_selectors:
        fun_name = fun_sig.split("(")[0]
        fun_info = FunctionInfo(contract_name, fun_name, fun_sig, fun_selector)

        try:
            # create a symbolic tx.origin
            tx_origin = mk_addr(
                f"halmos_tx_origin_{id_str(addr)}_{uid()}_{ex.new_symbol_id():>02}"
            )

            # create a symbolic msg.sender
            msg_sender = mk_addr(
                f"halmos_msg_sender_{id_str(addr)}_{uid()}_{ex.new_symbol_id():>02}"
            )

            # restrict msg.sender to the specified target senders.
            # follow foundry's behavior where:
            # - if effective_target_senders exist, consider them only.
            # - if no effective_target_senders but excluded_senders exist, consider excluded_senders only.
            # - otherwise, no restriction for sender.
            msg_sender_cond = (
                smt_or([msg_sender == target for target in effective_target_senders])
                if effective_target_senders
                else smt_and([msg_sender != excluded for excluded in excluded_senders])
                if excluded_senders
                else None
            )

            # create a symbolic msg.value
            msg_value = BitVec(
                f"halmos_msg_value_{id_str(addr)}_{uid()}_{ex.new_symbol_id():>02}",
                BitVecSort256,
            )

            yield from run_target_function(
                args,
                ex,
                addr,
                abi,
                fun_info,
                tx_origin,
                msg_sender,
                msg_value,
                msg_sender_cond,
            )

        except Exception as err:
            error(f"run_target_contract {addr} {fun_sig}: {type(err).__name__}: {err}")
            if args.debug:
                traceback.print_exc()
            continue


def _compute_frontier(ctx: ContractContext, depth: int) -> Iterator[Exec]:
    """
    Computes the frontier states at a given depth.

    This function iterates over the previous frontier states at `depth - 1` and executes an arbitrary function of an arbitrary target contract from each state.
    The resulting states form the new frontier at the current depth, which are yielded and also stored in the frontier state cache.

    NOTE: this is internal, only to be called by get_frontier().

    Args:
        ctx: The contract context containing the previous frontier states and other information.
        depth: The current depth level for which the frontier states are being computed.

    Returns:
        A generator for frontier states at the given depth.
    """
    frontier_states = ctx.frontier_states

    # frontier states at the previous depth, which will be used as input for computing new frontier states at the current depth
    curr_exs = frontier_states[depth - 1]

    # the cache for the new frontier states
    next_exs = []
    frontier_states[depth] = next_exs

    visited = ctx.visited

    args = ctx.args
    panic_error_codes = args.panic_error_codes
    flamegraph_enabled = args.flamegraph

    # create a dummy function context for handling counterexamples for probes.
    # this maintains the multithreaded solver executor for all probes at the current depth.
    dummy_function_ctx = FunctionContext(
        args=args,
        info=FunctionInfo(ctx.name, "_compute_frontier"),
        solver=None,
        contract_ctx=ctx,
        setup_ex=None,
        max_call_depth=None,
    )
    handler = CounterexampleHandler(
        ctx=dummy_function_ctx,
        is_invariant=True,
        is_probe=True,
        flamegraph_enabled=flamegraph_enabled,
        potential_flamegraphs={},
        submitted_futures=[],
    )
    path_id = 0

    contract_name = ctx.name
    for idx, pre_ex in enumerate(curr_exs):
        ui.update_status(
            f"{contract_name}: "
            f"depth: {cyan(depth)} | "
            f"starting states: {cyan(len(curr_exs))} | "
            f"unique states: {cyan(len(visited))} | "
            f"frontier states: {cyan(len(next_exs))} | "
            f"completed paths: {cyan(idx)} "
        )

        for addr in resolve_target_contracts(ctx.inv_ctx, pre_ex):
            # execute a target contract
            post_exs = run_target_contract(ctx, pre_ex, addr)

            for post_ex in post_exs:
                path_id += 1
                subcall = post_ex.context

                # update call sequences
                post_ex.call_sequence = pre_ex.call_sequence + [subcall]

                if flamegraph_enabled:
                    call_flamegraph.add_with_sequence(post_ex.call_sequence, subcall)

                # ignore and report if halmos-errored
                if subcall.is_stuck():
                    error(
                        f"{depth=}: addr={hexify(addr)}: {subcall.get_stuck_reason()}"
                    )
                    continue

                # ignore if reverted
                if subcall.output.error:
                    # ignore normal reverts
                    panic_found = post_ex.is_panic_of(panic_error_codes)
                    if not panic_found and not is_global_fail_set(subcall):
                        continue

                    fun_info = subcall.message.fun_info

                    # ignore if the probe has already been reported
                    if fun_info in ctx.probes_reported:
                        continue

                    msg = f"Assertion failure detected in {fun_info.contract_name}.{fun_info.sig}"

                    try:
                        handler.handle_assertion_violation(
                            path_id=path_id,
                            ex=post_ex,
                            panic_found=panic_found,
                            description=msg,
                        )
                    except ShutdownError:
                        if args.debug:
                            print(
                                "aborting path exploration, executor has been shutdown"
                            )
                        pass

                    # because this is a reverted state, we don't need to explore it further
                    continue

                # skip if already visited
                post_ex.path_slice()
                post_id = get_state_id(post_ex)
                if post_id in visited:
                    continue

                # update visited set
                # TODO: check path feasibility
                visited.add(post_id)

                # update timestamp
                timestamp_name = f"halmos_block_timestamp_depth{depth}_{uid()}"
                post_ex.block.timestamp = ZeroExt(192, BitVec(timestamp_name, 64))
                post_ex.path.append(post_ex.block.timestamp >= pre_ex.block.timestamp)

                # update the frontier states cache and yield the new frontier state
                next_exs.append(post_ex)
                yield post_ex


def get_frontier(ctx: ContractContext, depth: int) -> Iterable[Exec]:
    """
    Retrieves the frontier states at a given depth.

    If the frontier states have already been computed, the cached results are returned.
    Otherwise, the generator from _compute_frontier() is returned.

    NOTE: This is not thread-safe.
    Using the --early-exit option may result in incomplete exploration of the current depth if a counterexample is found during the first invariant test.
    As a result, subsequent tests might only consider a partially computed frontier.
    """
    if (frontier := ctx.frontier_states.get(depth)) is not None:
        return frontier

    return _compute_frontier(ctx, depth)


def run_message(
    ctx: FunctionContext, sevm: SEVM, message: Message, dyn_params: list
) -> Iterator[Exec]:
    """
    Executes the given test against all frontier states.

    A frontier state is the result of executing a sequence of arbitrary txs starting from the initial setup state.
    These states are grouped by their tx depth (i.e., the number of txs in a sequence) and cached in ContractContext.frontier_states to avoid re-computation for other tests.

    The max tx depth to consider is specified in FunctionContext, which is given by --invariant-depth for invariant tests, and set to 0 for regular tests.

    For regular tests (where the max tx depth is 0), this function amounts to executing the given test against only the initial setup state.
    """

    args = ctx.args
    contract_ctx = ctx.contract_ctx

    for depth in range(ctx.max_call_depth + 1):
        for ex in get_frontier(contract_ctx, depth):
            try:
                solver = mk_solver(args)

                path = Path(solver)
                path.extend_path(ex.path)
                path.process_dyn_params(dyn_params)

                yield from sevm.run_message(ex, message, path)

            finally:
                # reset any remaining solver states from the default context
                reset(solver)


@dataclass(frozen=True)
class CounterexampleHandler:
    """Handles potential assertion violations and generates counterexamples."""

    ctx: FunctionContext
    is_invariant: bool
    is_probe: bool
    flamegraph_enabled: bool
    potential_flamegraphs: dict
    submitted_futures: list

    def handle_assertion_violation(
        self,
        path_id: int,
        ex: Exec,
        panic_found: bool,
        description: str = None,
    ) -> None:
        """
        Handles a potential assertion violation by solving it in a separate process.

        This method processes a potential counterexample by creating a solver query
        and submitting it to the thread pool for asynchronous solving.

        Args:
            path_id: Unique identifier for the execution path
            ex: The execution state containing the potential violation
            panic_found: Whether it's a panic error or a legacy hevm.fail flag
            description: Optional description of the violation

        Raises:
            ShutdownError: If the executor has been shutdown during the solving process
        """
        ctx = self.ctx
        args = ctx.args

        if args.verbose >= 1:
            print(f"Found potential path with {path_id=} ", end="")
            output = ex.context.output
            error_output = output.error
            if panic_found:
                panic_code = unbox_int(output.data[4:36].unwrap())
                print(f"Panic(0x{panic_code:02x}) {error_output}")
            else:  # fail_found
                print(f"(fail flag set) {error_output}")

        # we don't know yet if this will lead to a counterexample
        # so we save the rendered trace here and potentially print it later
        # if a valid counterexample is found
        if args.verbose >= VERBOSITY_TRACE_COUNTEREXAMPLE:
            ctx.traces[path_id] = rendered_trace(ex.context)
        ctx.call_sequences[path_id] = rendered_call_sequence(ex.call_sequence)

        if self.flamegraph_enabled and self.is_invariant:
            # render the flamegraph to a temporary holder,
            # until we can confirm that it's a valid counterexample
            tmp_flamegraph = CallSequenceFlamegraph(title="Temp")
            tmp_flamegraph.add_with_sequence(
                ex.call_sequence, ex.context, mark_as_fail=True
            )
            self.potential_flamegraphs[path_id] = tmp_flamegraph

        query: SMTQuery = ex.path.to_smt2(args)

        # beware: because this object crosses thread boundaries, we must be careful to
        # avoid any reference to z3 objects
        path_ctx = PathContext(
            args=args,
            path_id=path_id,
            query=query,
            solving_ctx=ctx.solving_ctx,
        )

        # ShutdownError may be raised here and will be handled by the caller
        solve_future = ctx.thread_pool.submit(solve_end_to_end, path_ctx)
        solve_future.add_done_callback(
            partial(
                self._solve_end_to_end_callback,
                ex=ex,
                description=description,
            )
        )
        self.submitted_futures.append(solve_future)

    def _solve_end_to_end_callback(
        self, future: Future, ex: Exec, description: str
    ) -> None:
        """
        Callback function for handling solver results.

        Args:
            future: The Future object containing the solver result
            ex: The execution state
            description: Optional description of counterexample
        """
        # beware: this function may be called from threads other than the main thread,
        # so we must be careful to avoid referencing any z3 objects / contexts

        ctx = self.ctx
        args = ctx.args

        if e := future.exception():
            if isinstance(e, ShutdownError):
                if args.debug:
                    debug(
                        f"ignoring solver callback, executor has been shutdown: {e!r}"
                    )
                return

            error(f"encountered exception during assertion solving: {e!r}")

        #
        # we are done solving, process and triage the result
        #

        solver_output: SolverOutput = future.result()
        result, model = solver_output.result, solver_output.model

        if ctx.solving_ctx.executor.is_shutdown():
            # if the thread pool is in the process of shutting down,
            # we want to stop processing remaining models/timeouts/errors, etc.
            return

        # keep track of the solver outputs, so that we can display PASS/FAIL/TIMEOUT/ERROR later
        ctx.solver_outputs.append(solver_output)

        if result == unsat:
            if solver_output.unsat_core:
                ctx.append_unsat_core(solver_output.unsat_core)
            return

        if result == "err":
            error(
                f"solver error: {solver_output.error} (returncode={solver_output.returncode})"
            )
            return

        # model could be an empty dict here, so compare to None explicitly
        if model is None:
            return

        # mark this probe as reported to avoid duplicate reporting
        # note: message.fun_info is used instead of ctx.info because the function context for probes is dummy.
        if self.is_probe:
            ctx.contract_ctx.probes_reported.add(ex.context.message.fun_info)

        # print counterexample trace
        if description:
            print(description)

        path_id = solver_output.path_id
        if args.verbose >= VERBOSITY_TRACE_COUNTEREXAMPLE:
            pid_str = f" #{path_id}" if args.verbose >= VERBOSITY_TRACE_PATHS else ""
            print(f"Trace{pid_str}:")
            print(ctx.traces[path_id], end="")

        if model.is_valid:
            print(red(f"Counterexample: {model}"))
            ctx.valid_counterexamples.append(model)

            # add the stacks from the temporary flamegraph to the global one
            if self.flamegraph_enabled and self.is_invariant:
                call_flamegraph.stacks.extend(
                    self.potential_flamegraphs[path_id].stacks
                )

            # we have a valid counterexample, so we are eligible for early exit
            if args.early_exit:
                debug(f"Shutting down {ctx.info.name}'s solver executor")
                ctx.solving_ctx.executor.shutdown(wait=False)
        else:
            warn_str = f"Counterexample (potentially invalid): {model}"
            warn_code(COUNTEREXAMPLE_INVALID, warn_str)

            ctx.invalid_counterexamples.append(model)

        # print call sequence for invariant testing
        if sequence := ctx.call_sequences[path_id]:
            print(f"Sequence:\n{sequence}")


def run_test(ctx: FunctionContext) -> TestResult:
    args = ctx.args
    fun_info = ctx.info
    funname, funsig = fun_info.name, fun_info.sig

    if args.verbose >= 1:
        print(f"Executing {funname}")

    is_invariant = funname.startswith("invariant_")

    # set the config for every trace rendered in this test
    halmos.traces.config_context.set(args)

    #
    # prepare calldata
    #

    sevm = SEVM(args, fun_info)

    cd, dyn_params = mk_calldata(ctx.contract_ctx.abi, fun_info, args)

    message = Message(
        target=FOUNDRY_TEST,
        caller=FOUNDRY_CALLER,
        origin=FOUNDRY_ORIGIN,
        value=0,
        data=cd,
        call_scheme=EVM.CALL,
        fun_info=fun_info,
    )

    #
    # run
    #

    timer = NamedTimer("time")
    timer.create_subtimer("paths")

    exs = run_message(ctx, sevm, message, dyn_params)

    normal = 0
    potential = 0
    stuck = []

    flamegraph_enabled = args.flamegraph
    potential_flamegraphs: dict[int, CallSequenceFlamegraph] = {}
    submitted_futures = []

    handler = CounterexampleHandler(
        ctx=ctx,
        is_invariant=is_invariant,
        is_probe=False,
        flamegraph_enabled=flamegraph_enabled,
        potential_flamegraphs=potential_flamegraphs,
        submitted_futures=submitted_futures,
    )

    #
    # consume the sevm.run() generator
    # (actually triggers path exploration)
    #

    path_id = 0  # default value in case we don't enter the loop body
    for path_id, ex in enumerate(exs):
        # check if early exit is triggered
        if ctx.solving_ctx.executor.is_shutdown():
            if args.debug:
                print("aborting path exploration, executor has been shutdown")
            break

        # cache exec in case we need to print it later
        if args.print_failed_states:
            ctx.exec_cache[path_id] = ex

        if args.verbose >= VERBOSITY_TRACE_PATHS:
            ui.print(f"Path #{path_id}:\n{indent_text(hexify(ex.path))}")
            ui.print("\nTrace:")

            with suspend_status(ui.status):
                render_trace(ex.context)

        if flamegraph_enabled and not is_invariant:
            exec_flamegraph.add(ex.context)

        output = ex.context.output
        error_output = output.error
        panic_found = ex.is_panic_of(args.panic_error_codes)

        if panic_found or is_global_fail_set(ex.context):
            potential += 1

            try:
                handler.handle_assertion_violation(
                    path_id=path_id,
                    ex=ex,
                    panic_found=panic_found,
                )
            except ShutdownError:
                if args.debug:
                    print("aborting path exploration, executor has been shutdown")
                break

        elif ex.context.is_stuck():
            debug(f"Potential error path (id: {path_id})")
            path_ctx = PathContext(
                args=args,
                path_id=path_id,
                query=ex.path.to_smt2(args),
                solving_ctx=ctx.solving_ctx,
            )
            solver_output = solve_low_level(path_ctx)
            if solver_output.result != unsat:
                stuck.append((path_id, ex, ex.context.get_stuck_reason()))
                if args.print_blocked_states:
                    ctx.traces[path_id] = (
                        f"{hexify(ex.path)}\n{rendered_trace(ex.context)}"
                    )

        elif not error_output:
            if args.print_success_states:
                print(f"# {path_id}")
                print(ex)
            normal += 1

        # print post-states
        if args.print_states:
            print(f"# {path_id}")
            print(ex)
            print(rendered_call_sequence(ex.call_sequence))

        # 0 width is unlimited
        if args.width and path_id >= args.width:
            msg = "incomplete execution due to the specified limit"
            warn(f"{funsig}: {msg}: --width {args.width}")
            break

    num_execs = path_id + 1

    # the name is a bit misleading: this timer only starts after the exploration phase is complete
    # but it's possible that solvers have already been running for a while
    timer.create_subtimer("models")

    if potential > 0 and args.verbose >= 1:
        print(
            f"# of potential paths involving assertion violations: {potential} / {num_execs}"
            f" (--solver-threads {args.solver_threads})"
        )

    #
    # display assertion solving progress
    #

    if not args.no_status:
        while True:
            done = sum(fm.done() for fm in submitted_futures)
            total = potential
            if done == total:
                break
            elapsed = timedelta(seconds=int(timer.elapsed()))
            new_status = f"{funsig}: [{elapsed}] solving queries: {done} / {total}"
            ui.update_status(new_status)
            time.sleep(0.1)

    ctx.thread_pool.shutdown(wait=True)

    timer.stop()
    time_info = timer.report(include_subtimers=args.statistics)

    #
    # print test result
    #

    counter = Counter(str(m.result) for m in ctx.solver_outputs)
    if counter["sat"] > 0:
        passfail = red("[FAIL]")
        exitcode = Exitcode.COUNTEREXAMPLE.value
    elif counter["err"] > 0:
        passfail = red("[ERROR]")
        exitcode = Exitcode.EXCEPTION.value
    elif counter["unknown"] > 0:
        passfail = yellow("[TIMEOUT]")
        exitcode = Exitcode.TIMEOUT.value
    elif len(stuck) > 0:
        passfail = red("[ERROR]")
        exitcode = Exitcode.STUCK.value
    elif normal == 0:
        passfail = red("[ERROR]")
        exitcode = Exitcode.REVERT_ALL.value
        warn_code(
            REVERT_ALL,
            f"{funsig}: all paths have been reverted; the setup state or inputs may have been too restrictive.",
        )
    else:
        passfail = green("[PASS]")
        exitcode = Exitcode.PASS.value

    timer.stop()
    time_info = timer.report(include_subtimers=args.statistics)

    # print test result
    print(
        f"{passfail} {funsig} (paths: {num_execs}, {time_info}, "
        f"bounds: [{', '.join([str(x) for x in dyn_params])}])"
    )

    for path_id, _, err in stuck:
        warn_code(INTERNAL_ERROR, f"Encountered {type(err).__name__}: {err}")
        if args.print_blocked_states:
            print(f"\nPath #{path_id}")
            print(ctx.traces[path_id], end="")

    logs = sevm.logs
    if logs.bounded_loops:
        warn_code(
            LOOP_BOUND,
            f"{funsig}: paths have not been fully explored due to the loop unrolling bound: {args.loop}",
        )
        debug("\n".join(jumpid_str(x) for x in logs.bounded_loops))

    # return test result
    num_cexes = len(ctx.valid_counterexamples) + len(ctx.invalid_counterexamples)
    if args.minimal_json_output:
        return TestResult(funsig, exitcode, num_cexes)
    else:
        return TestResult(
            funsig,
            exitcode,
            num_cexes,
            ctx.valid_counterexamples + ctx.invalid_counterexamples,
            (num_execs, normal, len(stuck)),
            (timer.elapsed(), timer["paths"].elapsed(), timer["models"].elapsed()),
            len(logs.bounded_loops),
        )


def extract_setup(ctx: ContractContext) -> FunctionInfo:
    methodIdentifiers = ctx.method_identifiers
    setup_sigs = sorted(
        [
            (k, v)
            for k, v in methodIdentifiers.items()
            if k == "setUp()" or k.startswith("setUpSymbolic(")
        ]
    )

    if not setup_sigs:
        return FunctionInfo()

    (setup_sig, setup_selector) = setup_sigs[-1]
    setup_name = setup_sig.split("(")[0]
    return FunctionInfo(ctx.name, setup_name, setup_sig, setup_selector)


def reset(solver: Solver | None):
    if not solver:
        return

    if threading.current_thread() != threading.main_thread():
        # can't access z3 objects from other threads
        warn("reset() called from a non-main thread")

    solver.reset()


def get_invariant_testing_context(
    ctx: ContractContext, setup_ex: Exec
) -> InvariantTestingContext:
    # skip if forge-std/Test.sol is not imported
    if "targetSenders()" not in ctx.abi:
        return InvariantTestingContext.empty()

    try:
        return InvariantTestingContext(
            target_senders=get_target_senders(ctx, setup_ex),
            target_contracts=get_target_contracts(ctx, setup_ex),
            target_selectors=get_target_selectors(ctx, setup_ex),
            excluded_senders=get_excluded_senders(ctx, setup_ex),
            excluded_contracts=get_excluded_contracts(ctx, setup_ex),
            excluded_selectors=get_excluded_selectors(ctx, setup_ex),
        )
    except Exception as err:
        warn(
            f"An error occurred in get_invariant_testing_context and was ignored: {type(err).__name__}: {err}"
        )

    return InvariantTestingContext.empty()


def execute_simple_getter(
    ctx: ContractContext, setup_ex: Exec, fun_info: FunctionInfo
) -> ByteVec:
    """Executes a simple getter that takes no input, and returns the result."""

    args = ctx.args

    exs = run_target_function(
        args,
        setup_ex,
        FOUNDRY_TEST,
        ctx.abi,
        fun_info,
        FOUNDRY_ORIGIN,
        FOUNDRY_CALLER,
        0,
    )
    exs = list(exs)

    # sanity check
    if len(exs) != 1:
        raise HalmosException(f"{fun_info.sig}: # of paths: {len(exs)}")

    [ex] = exs

    output = ex.context.output
    returndata = output.data

    if output.error is not None or not returndata:
        raise HalmosException(f"{fun_info.sig}: {output.error=} {returndata=}")

    return returndata


def abi_decode_primitive_array(returndata: ByteVec) -> Iterator[Word]:
    """Decodes an array of primitive-type values."""

    offset = int_of(
        returndata.get_word(0),
        "symbolic offset for bytes argument",
    )

    length = int_of(
        returndata.get_word(offset),
        "symbolic size for bytes argument",
    )

    start = offset + 32
    for idx in range(length):
        item = returndata.get_word(start + idx * 32)
        yield item


def abi_decode_FuzzSelector_array(
    returndata: ByteVec,
) -> dict[Address, list[Bytes]]:
    """Decodes a FuzzSelector array."""

    offset = int_of(
        returndata.get_word(0),
        "symbolic offset for bytes argument",
    )
    length = int_of(
        returndata.get_word(offset),
        "symbolic size for bytes argument",
    )

    start = offset + 32
    result = defaultdict(list)

    for idx in range(length):
        item_offset = int_of(
            returndata.get_word(start + idx * 32),
            "symbolic offset for FuzzSelector items",
        )
        item_start = start + item_offset

        target_contract = con_addr(returndata.get_word(item_start))

        selectors = []

        selectors_offset = item_start + 64
        selectors_count = int_of(
            returndata.get_word(selectors_offset),
            "symbolic size for FuzzSelector items",
        )

        selectors_start = selectors_offset + 32
        for selector_idx in range(selectors_count):
            # read the first four bytes
            selector = extract_bytes(returndata, selectors_start + selector_idx * 32, 4)
            selectors.append(selector)

        # note that there may be multiple FuzzSelectors for the same target contract
        # so we don't want to stomp on the previous values
        result[target_contract].extend(selectors)

    return result


def get_target_senders(ctx: ContractContext, setup_ex: Exec) -> frozenset[Address]:
    # function targetSenders() public view returns (address[] memory targetedSenders_)
    selector = "3e5e3c23"
    funname = "targetSenders"
    fun_info = FunctionInfo(ctx.name, "funname", f"{funname}()", selector)

    returndata = execute_simple_getter(ctx, setup_ex, fun_info)
    return frozenset(con_addr(item) for item in abi_decode_primitive_array(returndata))


def get_excluded_senders(ctx: ContractContext, setup_ex: Exec) -> frozenset[Address]:
    # function excludeSenders() public view returns (address[] memory excludedSenders_)
    selector = "1ed7831c"
    funname = "excludeSenders"
    fun_info = FunctionInfo(ctx.name, "funname", f"{funname}()", selector)

    returndata = execute_simple_getter(ctx, setup_ex, fun_info)
    return frozenset(con_addr(item) for item in abi_decode_primitive_array(returndata))


def get_target_contracts(ctx: ContractContext, setup_ex: Exec) -> frozenset[Address]:
    # function targetContracts() public view returns (address[] memory targetedContracts_) {
    selector = "3f7286f4"
    funname = "targetContracts"
    fun_info = FunctionInfo(ctx.name, "funname", f"{funname}()", selector)

    returndata = execute_simple_getter(ctx, setup_ex, fun_info)
    return frozenset(con_addr(item) for item in abi_decode_primitive_array(returndata))


def get_excluded_contracts(ctx: ContractContext, setup_ex: Exec) -> frozenset[Address]:
    # function excludeContracts() public view returns (address[] memory excludedContracts_) {
    selector = "e20c9f71"
    funname = "excludeContracts"
    fun_info = FunctionInfo(ctx.name, "funname", f"{funname}()", selector)

    returndata = execute_simple_getter(ctx, setup_ex, fun_info)
    return frozenset(con_addr(item) for item in abi_decode_primitive_array(returndata))


def get_target_selectors(
    ctx: ContractContext, setup_ex: Exec
) -> MappingProxyType[Address, frozenset[Bytes]]:
    # function targetSelectors() public view returns (FuzzSelector[] memory targetedSelectors_) {
    selector = "916a17c6"
    funname = "targetSelectors"
    fun_info = FunctionInfo(ctx.name, "funname", f"{funname}()", selector)

    returndata = execute_simple_getter(ctx, setup_ex, fun_info)

    return MappingProxyType(
        {
            target: frozenset(selectors)
            for target, selectors in abi_decode_FuzzSelector_array(returndata).items()
        }
    )


def get_excluded_selectors(
    ctx: ContractContext, setup_ex: Exec
) -> MappingProxyType[Address, frozenset[Bytes]]:
    # function excludeSelectors() public view returns (FuzzSelector[] memory excludedSelectors_)
    selector = "b0464fdc"
    funname = "excludeSelectors"
    fun_info = FunctionInfo(ctx.name, "funname", f"{funname}()", selector)

    returndata = execute_simple_getter(ctx, setup_ex, fun_info)

    result = abi_decode_FuzzSelector_array(returndata)
    return MappingProxyType(
        {target: frozenset(selectors) for target, selectors in result.items()}
    )


# TODO: implement memoization to prevent redundant computation when ex.code remains unchanged
def resolve_target_contracts(ctx: InvariantTestingContext, ex: Exec) -> set[Address]:
    target_contracts = ctx.target_contracts
    target_selectors = ctx.target_selectors

    # conflict resolution as per foundry's behavior
    resolved_target_contracts = target_contracts if target_contracts else ex.code.keys()
    resolved_target_contracts -= ctx.excluded_contracts
    resolved_target_contracts |= target_selectors.keys()

    # Note: FOUNDRY_TEST is excluded unless a targetSelector() is specified for it
    # or targetContract(FOUNDRY_TEST) is provided.
    resolved_target_contracts = (
        resolved_target_contracts
        if (FOUNDRY_TEST in target_contracts or target_selectors.get(FOUNDRY_TEST))
        else resolved_target_contracts - {FOUNDRY_TEST}
    )

    if not resolved_target_contracts:
        raise HalmosException("No target contracts available.")

    return resolved_target_contracts


# TODO: implement memoization
def resolve_target_selectors(
    ctx: InvariantTestingContext, addr: Address, contract_json: dict
) -> Iterator[tuple[str, str]]:
    abi = get_abi(contract_json)
    method_identifiers = contract_json["methodIdentifiers"].items()

    # follow foundry's behavior where excludeSelector is ignored if targetSelector is given
    if target_selectors := ctx.target_selectors.get(addr):
        for fun_sig, fun_selector in method_identifiers:
            # TODO: Refactor contract_json to use bytes for method_identifiers instead of strings
            if bytes.fromhex(fun_selector) in target_selectors:
                yield (fun_sig, fun_selector)

    elif excluded_selectors := ctx.excluded_selectors.get(addr):
        for fun_sig, fun_selector in method_identifiers:
            if bytes.fromhex(fun_selector) not in excluded_selectors:
                yield (fun_sig, fun_selector)

    else:
        is_test_contract = eq(addr, FOUNDRY_TEST)

        for fun_sig, fun_selector in method_identifiers:
            # skip if 'pure' or 'view' function that doesn't change the state
            if (state_mutability := abi[fun_sig]["stateMutability"]) in [
                "pure",
                "view",
            ]:
                debug(f"Skipping {fun_sig} ({state_mutability})")
                continue

            # https://github.com/a16z/halmos/issues/514
            # exclude special functions like test_, check_, setUp(), etc.
            if is_test_contract and (
                fun_sig.startswith("test_")
                or fun_sig.startswith("check_")
                or fun_sig.startswith("prove_")
                or fun_sig.startswith("invariant_")
                or fun_sig == "setUp()"
                or fun_sig == "afterInvariant()"
            ):
                debug(f"Skipping {fun_sig} (reserved function)")
                continue

            yield (fun_sig, fun_selector)


def run_contract(ctx: ContractContext) -> list[TestResult]:
    BuildOut().set_build_out(ctx.build_out_map)

    args = ctx.args
    setup_info = extract_setup(ctx)
    setup_solver = None

    try:
        setup_config = with_devdoc(args, setup_info.sig, ctx.contract_json)

        if setup_config.debug_config:
            debug(f"config for setUp():\n{setup_config.formatted_layers()}")

        setup_solver = mk_solver(setup_config)
        setup_ctx = FunctionContext(
            args=setup_config,
            info=setup_info,
            solver=setup_solver,
            contract_ctx=ctx,
        )

        halmos.traces.config_context.set(setup_config)
        setup_ex = setup(setup_ctx)
        setup_ex.path_slice()
    except Exception as err:
        error(f"{setup_info.sig} failed: {type(err).__name__}: {err}")
        if args.debug:
            traceback.print_exc()

        # reset any remaining solver states from the default context
        reset(setup_solver)

        return []

    # initialize the frontier and visited states using the initial setup state
    ctx.frontier_states[0] = [setup_ex]
    ctx.visited.add(get_state_id(setup_ex))

    test_results = run_tests(ctx, setup_ex, ctx.funsigs)

    # reset any remaining solver states from the default context
    reset(setup_solver)

    return test_results


def print_invariant_targets(ctx: ContractContext, ex: Exec):
    try:
        target_contracts = resolve_target_contracts(ctx.inv_ctx, ex)
    except HalmosException:
        # no target contracts found, let the downstream tests fail
        target_contracts = []

    panel_content = []
    for target_contract in target_contracts:
        code = ex.code.get(target_contract)
        contract_name = code.contract_name
        filename = code.filename
        contract_json = BuildOut().get_by_name(contract_name, filename)

        addr_str = rendered_address(target_contract, replace_with_contract_name=False)
        tree = Tree(f"[bold]{filename}:{contract_name}[/bold] @ {addr_str}")

        target_selectors = resolve_target_selectors(
            ctx.inv_ctx, target_contract, contract_json
        )
        for fun_sig, _ in target_selectors:
            tree.add(f"{fun_sig}")

        panel_content.append(tree)
        panel_content.append(Text(""))

    if panel_content:
        # pop the last newline
        panel_content.pop()
        panel = Panel(
            Group(*panel_content),
            title="Initial Invariant Target Functions",
            border_style="blue",
            expand=False,
        )
        ui.print("\n", panel, "\n")


def run_tests(
    ctx: ContractContext,
    setup_ex: Exec,
    funsigs: list[str],
) -> list[TestResult]:
    """
    Executes each of the given test functions on the given input state.
    Used for both regular and invariant tests.

    Args:
        ctx: The context of the test contract.
        setup_ex: The setup state from which each test will be run.
        funsigs: A list of test function signatures to execute.

    Returns:
        A list of test results.
    """
    args = ctx.args

    test_results = []
    debug_config = args.debug_config

    # pretty print the target contracts and functions for invariant tests
    has_invariant_tests = any(funsig.startswith("invariant_") for funsig in funsigs)
    if has_invariant_tests:
        inv_ctx = get_invariant_testing_context(ctx, setup_ex)
        ctx.set_invariant_testing_context(inv_ctx)
        print_invariant_targets(ctx, setup_ex)

    for funsig in funsigs:
        selector = ctx.method_identifiers[funsig]
        fun_info = FunctionInfo(ctx.name, funsig.split("(")[0], funsig, selector)
        try:
            test_config = with_devdoc(args, funsig, ctx.contract_json)

            if debug_config:
                debug(f"config for {funsig}:\n{test_config.formatted_layers()}")

            max_call_depth = (
                test_config.invariant_depth if funsig.startswith("invariant_") else 0
            )

            test_ctx = FunctionContext(
                args=test_config,
                info=fun_info,
                solver=None,
                contract_ctx=ctx,
                setup_ex=setup_ex,
                max_call_depth=max_call_depth,
            )

            test_result = run_test(test_ctx)
        except Exception as err:
            print(f"{color_error('[ERROR]')} {funsig}")
            error(f"{type(err).__name__}: {err}")
            if args.debug:
                traceback.print_exc()
            test_results.append(TestResult(funsig, Exitcode.EXCEPTION.value))
            continue

        test_results.append(test_result)

    return test_results


def contract_regex(args):
    if contract := args.contract:
        return f"^{contract}$"
    else:
        return args.match_contract


def test_regex(args):
    match_test = args.match_test
    if match_test.startswith("^"):
        return match_test
    else:
        return f"^{args.function}.*{match_test}"


@dataclass(frozen=True)
class MainResult:
    exitcode: int
    # contract path -> list of test results
    test_results: dict[str, list[TestResult]] = None


def _main(_args=None) -> MainResult:
    timer = NamedTimer("total")
    timer.create_subtimer("build")

    #
    # z3 global options
    #

    set_option(max_width=240)
    set_option(max_lines=10**8)
    # set_option(max_depth=1000)

    #
    # command line arguments
    #

    args = load_config(_args)

    if args.version:
        print(f"halmos {metadata.version('halmos')}")
        return MainResult(0)

    init_env(args.root)

    if args.disable_gc:
        gc.disable()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger_unique.setLevel(logging.DEBUG)

    if args.trace_memory:
        import halmos.memtrace as memtrace

        memtrace.MemTracer.get().start()

    if args.flamegraph:
        flamegraph_installed = shutil.which("flamegraph.pl") is not None
        if flamegraph_installed:
            print(
                f"Flamegraphs will be written to {exec_flamegraph.out_filepath}"
                f" and {call_flamegraph.out_filepath}"
            )
        else:
            error(
                "flamegraph.pl not found in PATH (see https://github.com/brendangregg/FlameGraph)"
            )
            return MainResult(1)

    #
    # compile
    #

    build_cmd = [
        "forge",  # shutil.which('forge')
        "build",
        "--ast",
        "--root",
        args.root,
        "--extra-output",
        "storageLayout",
        "metadata",
    ]

    # force fresh build when coverage reporting enabled to generate correct source file ids
    if args.coverage_output:
        build_cmd.append("--force")

    # run forge without capturing stdout/stderr
    debug(f"Running {' '.join(build_cmd)}")

    build_exitcode = subprocess.run(build_cmd).returncode

    if build_exitcode:
        error(f"Build failed: {build_cmd}")
        return MainResult(1)

    ui.start_status()

    timer.create_subtimer("load")
    try:
        build_out = parse_build_out(args)
    except Exception as err:
        error(f"Build output parsing failed: {type(err).__name__}: {err}")
        if args.debug:
            traceback.print_exc()
        return MainResult(1)

    timer.create_subtimer("tests")

    total_passed = 0
    total_failed = 0
    total_found = 0
    test_results_map = {}

    #
    # exit and signal handlers to avoid dropping json output
    #

    def on_exit(exitcode: int) -> MainResult:
        ExecutorRegistry().shutdown_all()

        ui.stop_status()

        result = MainResult(exitcode, test_results_map)

        if args.json_output:
            debug(f"Writing output to {args.json_output}")
            with open(args.json_output, "w") as json_file:
                json.dump(asdict(result), json_file, indent=4)

        return result

    def on_signal(signum, frame):
        debug(f"Signal {signum} received")
        exitcode = 128 + signum
        on_exit(exitcode)
        sys.exit(exitcode)

    for signum in [signal.SIGINT, signal.SIGTERM]:
        signal.signal(signum, on_signal)

    #
    # run
    #

    _contract_regex = contract_regex(args)
    _test_regex = test_regex(args)

    for build_out_map, filename, contract_name in build_output_iterator(build_out):
        if not re.search(_contract_regex, contract_name):
            continue

        (contract_json, contract_type, natspec) = build_out_map[filename][contract_name]
        if contract_type != "contract":
            continue

        methodIdentifiers = contract_json["methodIdentifiers"]
        funsigs = [f for f in methodIdentifiers if re.search(_test_regex, f)]
        num_found = len(funsigs)

        if num_found == 0:
            continue

        contract_timer = NamedTimer("time")

        abi = get_abi(contract_json)
        creation_hexcode = contract_json["bytecode"]["object"]
        deployed_hexcode = contract_json["deployedBytecode"]["object"]
        linkReferences = contract_json["bytecode"]["linkReferences"]
        libs = import_libs(build_out_map, creation_hexcode, linkReferences)

        contract_path = f"{contract_json['ast']['absolutePath']}:{contract_name}"
        print(f"\nRunning {num_found} tests for {contract_path}")

        # Set the test contract address in DeployAddressMapper
        DeployAddressMapper().add_deployed_contract(hexify(FOUNDRY_TEST), contract_name)

        # support for `/// @custom:halmos` annotations
        contract_args = with_natspec(args, contract_name, natspec)
        contract_ctx = ContractContext(
            args=contract_args,
            name=contract_name,
            funsigs=funsigs,
            creation_hexcode=creation_hexcode,
            deployed_hexcode=deployed_hexcode,
            abi=abi,
            method_identifiers=methodIdentifiers,
            contract_json=contract_json,
            libs=libs,
            build_out_map=build_out_map,
        )

        test_results = run_contract(contract_ctx)
        num_passed = sum(r.exitcode == PASS for r in test_results)
        num_failed = num_found - num_passed

        print(
            "Symbolic test result: "
            f"{num_passed} passed; "
            f"{num_failed} failed; "
            f"{contract_timer.report()}"
        )

        total_found += num_found
        total_passed += num_passed
        total_failed += num_failed

        if contract_path in test_results_map:
            raise ValueError("already exists", contract_path)

        test_results_map[contract_path] = test_results

    if args.statistics:
        print(f"\n[time] {timer.report()}")

    if exec_flamegraph:
        exec_flamegraph.flush(force=True)

    if call_flamegraph:
        call_flamegraph.flush(force=True)

    if args.profile_instructions:
        profiler = Profiler()
        top_instructions = profiler.get_top_instructions()
        separator = "-" * 26
        print(separator)
        print(f"{'Instruction':<12} {'Count':>12}")
        print(separator)
        for instruction, count in top_instructions:
            print(f"{instruction:<12} {count:>12,}")
        print(separator)
        print(f"{'Total':<12} {profiler.counters.total():>12,}")
        print(separator)

    if coverage_file := args.coverage_output:
        with open(coverage_file, "w") as f:
            f.write(CoverageReporter().generate_lcov_report())
        print(f"Coverage report saved to: {coverage_file}")

    if total_found == 0:
        error(
            "No tests with"
            + f" --match-contract '{contract_regex(args)}'"
            + f" --match-test '{test_regex(args)}'"
        )
        return MainResult(1)

    exitcode = 0 if total_failed == 0 else 1
    return on_exit(exitcode)


# entrypoint for the `halmos` script
def main() -> int:
    exitcode = _main().exitcode
    return exitcode


# entrypoint for `python -m halmos`
if __name__ == "__main__":
    sys.exit(main())
