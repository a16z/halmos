# SPDX-License-Identifier: AGPL-3.0

import faulthandler
import gc
import json
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
import traceback
from collections import Counter
from concurrent.futures import Future
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import timedelta
from enum import Enum
from importlib import metadata

import rich
from z3 import (
    BitVec,
    ZeroExt,
    eq,
    set_option,
    unsat,
)

import halmos.traces

from .build import (
    build_output_iterator,
    import_libs,
    parse_build_out,
    parse_devdoc,
    parse_natspec,
)
from .bytevec import ByteVec
from .calldata import FunctionInfo, get_abi, mk_calldata
from .cheatcodes import snapshot_state
from .config import Config as HalmosConfig
from .config import arg_parser, default_config, resolve_config_files, toml_parser
from .constants import (
    VERBOSITY_TRACE_CONSTRUCTOR,
    VERBOSITY_TRACE_COUNTEREXAMPLE,
    VERBOSITY_TRACE_PATHS,
    VERBOSITY_TRACE_SETUP,
)
from .exceptions import HalmosException
from .logs import (
    COUNTEREXAMPLE_INVALID,
    COUNTEREXAMPLE_UNKNOWN,
    INTERNAL_ERROR,
    LOOP_BOUND,
    REVERT_ALL,
    debug,
    error,
    logger,
    logger_unique,
    progress_status,
    warn,
    warn_code,
)
from .mapper import BuildOut, DeployAddressMapper
from .processes import ExecutorRegistry, ShutdownError
from .sevm import (
    EMPTY_BALANCE,
    EVM,
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
    FailCheatcode,
    Message,
    Path,
    SMTQuery,
    con_addr,
    id_str,
    jumpid_str,
    mnemonic,
)
from .solve import (
    ContractContext,
    FunctionContext,
    InvariantContext,
    PathContext,
    SolverOutput,
    solve_end_to_end,
    solve_low_level,
)
from .traces import render_trace, rendered_trace
from .utils import (
    Address,
    BitVecSort256,
    NamedTimer,
    address,
    color_error,
    con,
    create_solver,
    cyan,
    green,
    hexify,
    indent_text,
    red,
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


def with_devdoc(args: HalmosConfig, fn_sig: str, contract_json: dict) -> HalmosConfig:
    devdoc = parse_devdoc(fn_sig, contract_json)
    if not devdoc:
        return args

    overrides = arg_parser().parse_args(devdoc.split())
    return args.with_overrides(source=fn_sig, **vars(overrides))


def with_natspec(
    args: HalmosConfig, contract_name: str, contract_natspec: str
) -> HalmosConfig:
    if not contract_natspec:
        return args

    parsed = parse_natspec(contract_natspec)
    if not parsed:
        return args

    overrides = arg_parser().parse_args(parsed.split())
    return args.with_overrides(source=contract_name, **vars(overrides))


def load_config(_args) -> HalmosConfig:
    config = default_config()

    if not config.solver_command:
        warn(
            "could not find z3 on the PATH -- check your PATH/venv or pass --solver-command explicitly"
        )

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
        config = config.with_overrides(source=config_file, **overrides)

    # finally apply the CLI overrides
    config = config.with_overrides(source="command line args", **vars(cli_overrides))

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


def mk_this() -> Address:
    # NOTE: Do NOT remove the `con_addr()` wrapper.
    #       The return type should be BitVecSort(160) as it is used as a key for ex.code.
    #       The keys of ex.code are compared using structural equality with other BitVecRef addresses.
    return con_addr(FOUNDRY_TEST)


def mk_solver(args: HalmosConfig, logic="QF_AUFBV", ctx=None):
    return create_solver(
        logic=logic,
        ctx=ctx,
        timeout=args.solver_timeout_branching,
        max_memory=args.solver_max_memory,
    )


def deploy_test(ctx: FunctionContext, sevm: SEVM) -> Exec:
    this = mk_this()
    message = Message(
        target=this,
        caller=FOUNDRY_CALLER,
        origin=FOUNDRY_ORIGIN,
        value=0,
        data=ByteVec(),
        call_scheme=EVM.CREATE,
    )

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
        raise ValueError(f"constructor: # of paths: {len(exs)}")

    [ex] = exs

    if ctx.args.verbose >= VERBOSITY_TRACE_CONSTRUCTOR:
        print("Constructor trace:")
        render_trace(ex.context)

    error_output = ex.context.output.error
    returndata = ex.context.output.data
    if error_output:
        raise ValueError(
            f"constructor failed, error={error_output} returndata={returndata}"
        )

    deployed_bytecode = Contract(returndata)
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

    parent_message = setup_ex.message()
    setup_ex.context = CallContext(
        message=Message(
            target=parent_message.target,
            caller=parent_message.caller,
            origin=parent_message.origin,
            value=0,
            data=calldata,
            call_scheme=EVM.CALL,
        ),
    )

    setup_exs_all = sevm.run(setup_ex)
    setup_exs_no_error: list[tuple[Exec, SMTQuery]] = []

    for path_id, setup_ex in enumerate(setup_exs_all):
        if args.verbose >= VERBOSITY_TRACE_SETUP:
            print(f"{setup_sig} trace #{path_id}:")
            render_trace(setup_ex.context)

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


def run_invariant_tests(
    ctx: ContractContext, pre_ex: Exec, funsigs: list[str]
) -> list[TestResult]:
    """
    Executes invariant test functions across multiple depths, reusing states at each depth for all invariant functions.

    At each depth, starting from a given state, an arbitrary transaction is executed on every target contract, producing output states.
    All invariant tests are then executed on each of these output states.
    The process continues to the next depth, using these output states as the new input.

    Args:
        ctx: The context for the test contract.
        pre_ex: The initial state from which invariant tests will be run.
        funsigs: A list of invariant test function signatures to be executed.

    Returns:
        A list of test results.
    """
    args = ctx.args

    # check all invariants against the initial state
    test_results = run_tests(ctx, pre_ex, funsigs, terminal=False)

    # initial test results; to be updated later
    test_results_map = {r.name: r for r in test_results}

    # Remaining tests that have not failed yet, to be executed in the next depth
    funsigs = [r.name for r in test_results if r.exitcode == PASS]

    # if no more invariant tests to run, stop
    if not funsigs:
        return test_results_map.values()

    # dynamic set of visited states, initialized with the initial state
    visited = set()
    visited.add(get_state_id(pre_ex))

    # dynamic list of frontier states
    exs = [pre_ex]

    # mutable context for invariant testing loop over multiple depths
    inv_ctx = InvariantContext(
        contract_ctx=ctx,
        visited=visited,
        test_results_map=test_results_map,
    )

    depth = 0
    # invariant_depth can be overridden by specific test functions, so not checked here
    while True:
        depth += 1

        # given the input states `exs`, generate output states and perform invariant tests `funsigs` on them.
        # update `exs` with the new output states, and `funsigs` with remaining invariant tests for the next depth.
        exs, funsigs = step_invariant_tests(inv_ctx, exs, funsigs, depth)

        # TODO: merge, simplify, or prioritize exs to mitigate path explosion

        if args.debug:
            print(f"{depth=}\n")
            for idx, ex in enumerate(exs):
                print(f"{idx=} {hexify(get_state_id(ex))=}\n")
                print(ex)
                render_trace(ex.context)

        # stop if no new frontier states or remaining invariant tests
        if not exs or not funsigs:
            break

    test_results = test_results_map.values()

    # print passed tests; failed tests have already been displayed during step_invariant_tests()
    for r in test_results:
        if r.exitcode == PASS:
            print(
                f"{green('[PASS]')} {r.name} (depth: {depth - 1}, paths: {len(visited)})"
            )

    return test_results


def step_invariant_tests(
    inv_ctx: InvariantContext,
    pre_exs: list[Exec],
    funsigs: list[str],
    depth: int,
) -> tuple[list[Exec], list[str]]:
    """
    Executes the next depth of the invariant testing run, which consists of:
    1. Computing new frontier states by executing an arbitrary function of an arbitrary target contract from each of the given input states.
    2. Executing invariant tests for each new frontier state.
    3. Returning the new frontier states that have not been visited.

    Args:
        inv_ctx: The context for the invariant testing run.
        pre_exs: A list of input states.
        funsigs: A list of invariant test function signatures to be executed at this depth.
        depth: The current depth of the invariant testing run.

    Returns:
        A list of new frontier states generated at this depth.
        A list of invariant test function signatures remaining for the next depth.
    """
    ctx = inv_ctx.contract_ctx
    test_results_map = inv_ctx.test_results_map
    visited = inv_ctx.visited

    next_exs = []

    for idx, pre_ex in enumerate(pre_exs):
        progress_status.update(
            f"depth: {cyan(depth)} | "
            f"starting states: {cyan(len(pre_exs))} | "
            f"unique states: {cyan(len(visited))} | "
            f"frontier states: {cyan(len(next_exs))} | "
            f"completed paths: {cyan(idx)} "
        )

        for addr in pre_ex.code:
            # skip the test contract
            if eq(addr, con_addr(FOUNDRY_TEST)):
                continue

            # execute a target contract
            post_exs = run_target_contract(ctx, pre_ex, addr)

            for post_ex in post_exs:
                subcall = post_ex.context

                # ignore and report if halmos-errored
                if subcall.is_stuck():
                    error(
                        f"{depth=}: addr={hexify(addr)}: {subcall.get_stuck_reason()}"
                    )
                    continue

                # ignore if reverted
                if subcall.output.error:
                    continue

                # skip if already visited
                post_ex.path_slice()
                post_id = get_state_id(post_ex)
                if post_id in visited:
                    continue

                # update visited set
                # TODO: check path feasibility
                visited.add(post_id)

                # update call traces
                post_ex.context = deepcopy(pre_ex.context)
                post_ex.context.trace.append(subcall)

                # update timestamp
                timestamp_name = f"halmos_block_timestamp_depth{depth}_{uid()}"
                post_ex.block.timestamp = ZeroExt(192, BitVec(timestamp_name, 64))
                post_ex.path.append(post_ex.block.timestamp >= pre_ex.block.timestamp)

                # check all invariants against the current output state
                test_results = run_tests(ctx, post_ex, funsigs, depth, terminal=False)

                # update the test results
                test_results_map.update({r.name: r for r in test_results})

                # update remaining invariant tests
                funsigs = [r.name for r in test_results if r.exitcode == PASS]

                # print call trace if failed, to provide additional info for counterexamples
                if any(r.exitcode != PASS for r in test_results):
                    print("Path:")
                    print(indent_text(hexify(post_ex.path)))

                    print("\nTrace:")
                    render_trace(post_ex.context)

                # stop if no more invariants to test
                if not funsigs:
                    return next_exs, funsigs

                # update the frontier states to be returned.
                # NOTE: this state excludes any changes made during the execution of invariant test functions to prevent unnecessary increases in path condition complexity.
                next_exs.append(post_ex)

    return next_exs, funsigs


def run_target_contract(ctx: ContractContext, ex: Exec, addr: Address) -> list[Exec]:
    """
    Executes a given contract from a given input state and returns all output states.

    Args:
        ctx: The context of the test contract, which differs from the target contract to be executed.
        ex: The input state.
        addr: The address of the contract to be executed.

    Returns:
        A list of output states.

    Raises:
        ValueError: If the contract name cannot be found for the given address.
    """
    args = ctx.args

    # retrieve the contract name and metadata from the given address
    code = ex.code[addr]
    contract_name = code.contract_name
    filename = code.filename

    if not contract_name:
        raise ValueError(f"couldn't find the contract name for: {addr}")

    contract_json = BuildOut().get_by_name(contract_name, filename)
    abi = get_abi(contract_json)
    method_identifiers = contract_json["methodIdentifiers"]

    results = []

    # iterate over each function in the target contract
    for fun_sig, fun_selector in method_identifiers.items():
        fun_name = fun_sig.split("(")[0]
        fun_info = FunctionInfo(fun_name, fun_sig, fun_selector)

        # skip if 'pure' or 'view' function that doesn't change the state
        state_mutability = abi[fun_sig]["stateMutability"]
        if state_mutability in ["pure", "view"]:
            if args.debug:
                print(f"Skipping {fun_name} ({state_mutability})")
            continue

        try:
            # initialize symbolic execution environment
            sevm = SEVM(args, fun_info)
            # TODO: reuse solver across different functions
            solver = mk_solver(args)
            path = Path(solver)
            path.extend_path(ex.path)

            # prepare calldata and dynamic parameters
            cd, dyn_params = mk_calldata(
                abi, fun_info, args, new_symbol_id=ex.new_symbol_id
            )
            path.process_dyn_params(dyn_params)

            # create a symbolic tx.origin
            tx_origin = mk_addr(
                f"tx_origin_{id_str(addr)}_{uid()}_{ex.new_symbol_id():>02}"
            )

            # create a symbolic msg.sender
            msg_sender = mk_addr(
                f"msg_sender_{id_str(addr)}_{uid()}_{ex.new_symbol_id():>02}"
            )

            # create a symbolic msg.value
            msg_value = BitVec(
                f"msg_value_{id_str(addr)}_{uid()}_{ex.new_symbol_id():>02}",
                BitVecSort256,
            )

            # construct the transaction message
            message = Message(
                target=addr,
                caller=msg_sender,
                origin=tx_origin,
                value=msg_value,
                data=cd,
                call_scheme=EVM.CALL,
            )

            # execute the transaction and collect output states
            results.extend(sevm.run_message(ex, message, path))

        except Exception as err:
            error(f"run_target_contract {addr} {fun_sig}: {type(err).__name__}: {err}")
            if args.debug:
                traceback.print_exc()
            continue

        finally:
            reset(solver)

    return results


def run_test(ctx: FunctionContext) -> TestResult:
    args = ctx.args
    fun_info = ctx.info
    funname, funsig = fun_info.name, fun_info.sig
    if args.verbose >= 1:
        print(f"Executing {funname}")

    # set the config for every trace rendered in this test
    halmos.traces.config_context.set(args)

    #
    # prepare calldata
    #

    setup_ex = ctx.setup_ex
    sevm = SEVM(args, fun_info)
    path = Path(ctx.solver)
    path.extend_path(setup_ex.path)

    cd, dyn_params = mk_calldata(ctx.contract_ctx.abi, fun_info, args)
    path.process_dyn_params(dyn_params)

    message = Message(
        target=setup_ex.this(),
        caller=setup_ex.caller(),
        origin=setup_ex.origin(),
        value=0,
        data=cd,
        call_scheme=EVM.CALL,
    )

    #
    # run
    #

    timer = NamedTimer("time")
    timer.create_subtimer("paths")

    exs = sevm.run_message(setup_ex, message, path)

    normal = 0
    potential = 0
    stuck = []

    def solve_end_to_end_callback(future: Future):
        # beware: this function may be called from threads other than the main thread,
        # so we must be careful to avoid referencing any z3 objects / contexts

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

        solver_output = future.result()
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

        # model could be an empty dict here, so compare to None explicitly
        if model is None:
            warn_code(COUNTEREXAMPLE_UNKNOWN, f"Counterexample: {result}")
            return

        # print counterexample trace
        if args.verbose >= VERBOSITY_TRACE_COUNTEREXAMPLE:
            path_id = solver_output.path_id
            pid_str = f" #{path_id}" if args.verbose >= VERBOSITY_TRACE_PATHS else ""
            print(f"Trace{pid_str}:")
            print(ctx.traces[path_id], end="")

        if model.is_valid:
            print(red(f"Counterexample: {model}"))
            ctx.valid_counterexamples.append(model)

            # we have a valid counterexample, so we are eligible for early exit
            if args.early_exit:
                debug(f"Shutting down {ctx.info.name}'s solver executor")
                ctx.solving_ctx.executor.shutdown(wait=False)
        else:
            warn_str = f"Counterexample (potentially invalid): {model}"
            warn_code(COUNTEREXAMPLE_INVALID, warn_str)

            ctx.invalid_counterexamples.append(model)

    #
    # consume the sevm.run() generator
    # (actually triggers path exploration)
    #

    path_id = 0  # default value in case we don't enter the loop body
    submitted_futures = []
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
            print(f"Path #{path_id}:")
            print(indent_text(hexify(ex.path)))

            print("\nTrace:")
            render_trace(ex.context)

        output = ex.context.output
        error_output = output.error
        panic_found = ex.is_panic_of(args.panic_error_codes)

        if panic_found or (fail_found := is_global_fail_set(ex.context)):
            potential += 1

            if args.verbose >= 1:
                print(f"Found potential path with {path_id=} ", end="")
                if panic_found:
                    panic_code = unbox_int(output.data[4:36].unwrap())
                    print(f"Panic(0x{panic_code:02x}) {error_output}")
                elif fail_found:
                    print(f"(fail flag set) {error_output}")

            # we don't know yet if this will lead to a counterexample
            # so we save the rendered trace here and potentially print it later
            # if a valid counterexample is found
            if args.verbose >= VERBOSITY_TRACE_COUNTEREXAMPLE:
                ctx.traces[path_id] = rendered_trace(ex.context)

            query: SMTQuery = ex.path.to_smt2(args)

            # beware: because this object crosses thread boundaries, we must be careful to
            # avoid any reference to z3 objects
            path_ctx = PathContext(
                args=args,
                path_id=path_id,
                query=query,
                solving_ctx=ctx.solving_ctx,
            )

            try:
                solve_future = ctx.thread_pool.submit(solve_end_to_end, path_ctx)
                solve_future.add_done_callback(solve_end_to_end_callback)
                submitted_futures.append(solve_future)
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
            progress_status.update(f"[{elapsed}] solving queries: {done} / {total}")
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
    # TODO: improve test result display logic for invariant tests
    if ctx.terminal or exitcode != PASS:
        print(
            f"{passfail} {funsig} (paths: {num_execs}, {time_info}, "
            f"bounds: [{', '.join([str(x) for x in dyn_params])}])"
        )

    for path_id, _, err in stuck:
        warn_code(INTERNAL_ERROR, f"Encountered {err}")
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


def extract_setup(methodIdentifiers: dict[str, str]) -> FunctionInfo:
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
    return FunctionInfo(setup_name, setup_sig, setup_selector)


def reset(solver):
    if threading.current_thread() != threading.main_thread():
        # can't access z3 objects from other threads
        warn("reset() called from a non-main thread")

    solver.reset()


def run_contract(ctx: ContractContext) -> list[TestResult]:
    BuildOut().set_build_out(ctx.build_out_map)

    args = ctx.args
    setup_info = extract_setup(ctx.method_identifiers)

    try:
        setup_config = with_devdoc(args, setup_info.sig, ctx.contract_json)
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

    # separate regular and invariant tests
    test_funsigs, inv_funsigs = [], []
    for sig in ctx.funsigs:
        (inv_funsigs if sig.startswith("invariant_") else test_funsigs).append(sig)

    test_results = []

    # execute regular tests
    if test_funsigs:
        test_results.extend(run_tests(ctx, setup_ex, test_funsigs))

    # execute invariant tests
    if inv_funsigs:
        test_results.extend(run_invariant_tests(ctx, setup_ex, inv_funsigs))

    # reset any remaining solver states from the default context
    reset(setup_solver)

    return test_results


def run_tests(
    ctx: ContractContext,
    pre_ex: Exec,
    funsigs: list[str],
    depth: int = 0,
    terminal: bool = True,
) -> list[TestResult]:
    """
    Executes each of the given test functions on the given input state.
    Used for both regular and invariant tests.

    Args:
        ctx: The context of the test contract.
        pre_ex: The input state from which each test will be run.
        funsigs: A list of test function signatures to execute.
        depth (optional, only for invariant testing): The current depth of the invariant testing run.
        terminal (optional, only for invariant testing): A flag indicating whether this testing run is final.

    Returns:
        A list of test results.
    """
    args = ctx.args

    test_results = []
    debug_config = args.debug_config

    for funsig in funsigs:
        selector = ctx.method_identifiers[funsig]
        fun_info = FunctionInfo(funsig.split("(")[0], funsig, selector)
        try:
            test_config = with_devdoc(args, funsig, ctx.contract_json)
            # TODO: reuse solver across different functions
            solver = mk_solver(test_config)
            if debug_config:
                debug(f"{test_config.formatted_layers()}")

            # stop if the current depth exceeds the max depth for the test.
            # note that the max depth may vary across tests.
            # no-op for regular tests where depth is 0.
            if depth > test_config.invariant_depth:
                continue

            test_ctx = FunctionContext(
                args=test_config,
                info=fun_info,
                solver=solver,
                contract_ctx=ctx,
                setup_ex=pre_ex,
                terminal=terminal,
            )

            test_result = run_test(test_ctx)
        except Exception as err:
            print(f"{color_error('[ERROR]')} {funsig}")
            error(f"{type(err).__name__}: {err}")
            if args.debug:
                traceback.print_exc()
            test_results.append(TestResult(funsig, Exitcode.EXCEPTION.value))
            continue
        finally:
            # reset any remaining solver states from the default context
            reset(solver)

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

    # clear any remaining live display before starting a new instance
    rich.get_console().clear_live()
    progress_status.start()

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

    if args.disable_gc:
        gc.disable()

    if args.debug:
        logger.setLevel(logging.DEBUG)
        logger_unique.setLevel(logging.DEBUG)

    if args.trace_memory:
        import halmos.memtrace as memtrace

        memtrace.MemTracer.get().start()

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

    # run forge without capturing stdout/stderr
    debug(f"Running {' '.join(build_cmd)}")

    build_exitcode = subprocess.run(build_cmd).returncode

    if build_exitcode:
        error(f"Build failed: {build_cmd}")
        return MainResult(1)

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

        progress_status.stop()

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
        DeployAddressMapper().add_deployed_contract(hexify(mk_this()), contract_name)

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
