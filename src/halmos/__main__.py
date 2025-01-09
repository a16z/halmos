# SPDX-License-Identifier: AGPL-3.0

import gc
import json
import logging
import os
import re
import signal
import subprocess
import sys
import time
import traceback
import uuid
from collections import Counter
from concurrent.futures import Future, ThreadPoolExecutor
from copy import deepcopy
from dataclasses import asdict, dataclass, field
from datetime import timedelta
from enum import Enum
from importlib import metadata

from z3 import (
    BitVec,
    CheckSatResult,
    Solver,
    sat,
    set_option,
    unknown,
    unsat,
)

from .bytevec import ByteVec
from .calldata import FunctionInfo, get_abi, mk_calldata
from .config import Config as HalmosConfig
from .config import arg_parser, default_config, resolve_config_files, toml_parser
from .exceptions import HalmosException
from .logs import (
    COUNTEREXAMPLE_INVALID,
    COUNTEREXAMPLE_UNKNOWN,
    INTERNAL_ERROR,
    LOOP_BOUND,
    PARSING_ERROR,
    REVERT_ALL,
    debug,
    error,
    logger,
    logger_unique,
    warn,
    warn_code,
)
from .mapper import BuildOut, DeployAddressMapper, Mapper
from .processes import PopenExecutor, PopenFuture
from .sevm import (
    EMPTY_BALANCE,
    EVM,
    FOUNDRY_CALLER,
    FOUNDRY_ORIGIN,
    FOUNDRY_TEST,
    ONE,
    SEVM,
    ZERO,
    Address,
    Block,
    CallContext,
    CallOutput,
    Contract,
    Exec,
    FailCheatcode,
    Message,
    Path,
    SMTQuery,
    State,
    con_addr,
    jumpid_str,
    mnemonic,
)
from .smtlib import ModelVariables, parse_string
from .traces import render_trace, rendered_trace
from .utils import (
    NamedTimer,
    address,
    color_error,
    con,
    create_solver,
    green,
    hexify,
    indent_text,
    red,
    stringify,
    unbox_int,
    yellow,
)

# Python version >=3.8.14, >=3.9.14, >=3.10.7, or >=3.11
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(0)

# we need to be able to process at least the max message depth (1024)
sys.setrecursionlimit(1024 * 4)

# sometimes defaults to cp1252 on Windows, which can cause UnicodeEncodeError
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

VERBOSITY_TRACE_COUNTEREXAMPLE = 2
VERBOSITY_TRACE_SETUP = 3
VERBOSITY_TRACE_PATHS = 4
VERBOSITY_TRACE_CONSTRUCTOR = 5


@dataclass
class PotentialModel:
    model: ModelVariables | str | None
    is_valid: bool

    def __str__(self) -> str:
        # expected to be a filename
        if isinstance(self.model, str):
            return f"see {self.model}"

        formatted = []
        for v in self.model.values():
            # TODO: ideally we would avoid wrapping with con() here
            stringified = stringify(v.full_name, con(v.value))
            formatted.append(f"\n    {v.full_name} = {stringified}")
        return "".join(sorted(formatted)) if formatted else "∅"


@dataclass(frozen=True)
class ContractContext:
    # config with contract-specific overrides
    args: HalmosConfig

    # name of this contract
    name: str

    # signatures of test functions to run
    funsigs: list[str]

    # data parsed from the build output for this contract
    creation_hexcode: str
    deployed_hexcode: str
    abi: dict
    method_identifiers: dict[str, str]
    contract_json: dict
    libs: dict

    # TODO: check if this is really a contract-level variable
    build_out_map: dict


@dataclass(frozen=True)
class FunctionContext:
    # config with function-specific overrides
    args: HalmosConfig

    # function name, signature, and selector
    info: FunctionInfo

    # solver using the function-specific config
    solver: Solver

    # backlink to the parent contract context
    contract_ctx: ContractContext

    # optional starting state
    setup_ex: Exec | None = None

    # dump directory for this function (generated in __post_init__)
    dump_dirname: str = field(init=False)

    # function-level thread pool that drives assertion solving
    thread_pool: ThreadPoolExecutor = field(init=False)

    # path-specific queries are submitted to this function-specific executor
    solver_executor: PopenExecutor = field(default_factory=PopenExecutor)

    # list of solver outputs for this function
    _solver_outputs: list["SolverOutput"] = field(default_factory=list)

    # list of valid counterexamples for this function
    valid_counterexamples: list[PotentialModel] = field(default_factory=list)

    # list of potentially invalid counterexamples for this function
    invalid_counterexamples: list[PotentialModel] = field(default_factory=list)

    # list of unsat cores for this function
    unsat_cores: list[list] = field(default_factory=list)

    # map from path id to trace
    traces: dict[int, str] = field(default_factory=dict)

    # map from path id to execution
    exec_cache: dict[int, Exec] = field(default_factory=dict)

    def __post_init__(self):
        dirname = f"/tmp/{self.info.name}-{uuid.uuid4().hex}"
        object.__setattr__(self, "dump_dirname", dirname)

        thread_pool = ThreadPoolExecutor(
            max_workers=self.args.solver_threads,
            thread_name_prefix=f"{self.info.name}-",
        )
        object.__setattr__(self, "thread_pool", thread_pool)

    @property
    def solver_outputs(self):
        return self._solver_outputs


@dataclass(frozen=True)
class PathContext:
    # id of this path
    path_id: int

    # path execution object
    ex: Exec

    # SMT query
    query: SMTQuery

    # backlink to the parent function context
    fun_ctx: FunctionContext

    # filename for this path (generated in __post_init__)
    dump_filename: str = field(init=False)

    is_refined: bool = False

    def __post_init__(self):
        refined_str = ".refined" if self.is_refined else ""
        dirname = self.fun_ctx.dump_dirname
        filename = os.path.join(dirname, f"{self.path_id}{refined_str}.smt2")

        # use __setattr__ because this is a frozen dataclass
        object.__setattr__(self, "dump_filename", filename)

    def refine(self) -> "PathContext":
        return PathContext(
            path_id=self.path_id,
            ex=self.ex,
            query=refine(self.query),
            fun_ctx=self.fun_ctx,
            is_refined=True,
        )


@dataclass(frozen=True)
class SolverOutput:
    # solver result
    result: CheckSatResult

    # we don't backlink to the parent path context to avoid extra
    # references to Exec objects past the lifetime of the path
    path_id: int

    # solver model
    model: PotentialModel | None = None

    # optional unsat core
    unsat_core: list[str] | None = None

    @staticmethod
    def from_result(
        stdout: str, stderr: str, returncode: int, path_ctx: PathContext
    ) -> "SolverOutput":
        # extract the first line (we expect sat/unsat/unknown)
        newline_idx = stdout.find("\n")
        first_line = stdout[:newline_idx] if newline_idx != -1 else stdout

        args = path_ctx.fun_ctx.args
        path_id = path_ctx.path_id
        if args.verbose >= 1:
            debug(f"    {first_line}")

        match first_line:
            case "unsat":
                unsat_core = parse_unsat_core(stdout) if args.cache_solver else None
                return SolverOutput(unsat, path_id, unsat_core=unsat_core)
            case "sat":
                is_valid = is_model_valid(stdout)
                model = PotentialModel(model=parse_string(stdout), is_valid=is_valid)
                return SolverOutput(sat, path_id, model=model)
            case _:
                return SolverOutput(unknown, path_id)


@dataclass(frozen=True)
class TestResult:
    name: str  # test function name
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
        balance=EMPTY_BALANCE,
        block=mk_block(),
        context=CallContext(message=message),
        pgm=None,  # to be added
        path=Path(ctx.solver),
    )

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
    ex.pc = 0
    ex.st = State()
    ex.context.output = CallOutput()
    ex.jumpis = {}

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

    setup_timer.create_subtimer("run")

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
    setup_exs_no_error: list[PathContext] = []

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
            path_ctx = PathContext(
                path_id=path_id,
                ex=setup_ex,
                query=setup_ex.path.to_smt2(args),
                fun_ctx=ctx,
            )
            setup_exs_no_error.append(path_ctx)

    setup_exs: list[Exec] = []

    match len(setup_exs_no_error):
        case 0:
            pass
        case 1:
            setup_exs.append(setup_exs_no_error[0][0])
        case _:
            for path_ctx in setup_exs_no_error:
                solver_output = solve_low_level(path_ctx)
                if solver_output.result != unsat:
                    setup_exs.append(path_ctx.ex)
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


def run_test(ctx: FunctionContext) -> TestResult:
    args = ctx.args
    fun_info = ctx.info
    funname, funsig = fun_info.name, fun_info.sig
    if args.verbose >= 1:
        print(f"Executing {funname}")

    #
    # prepare test dump directory if needed
    #

    dump_dirname = ctx.dump_dirname
    should_dump = args.dump_smt_queries or args.solver_command
    if should_dump and not os.path.isdir(dump_dirname):
        os.makedirs(dump_dirname)
        print(f"Generating SMT queries in {dump_dirname}")

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
    sevm.status_start()

    exs = sevm.run(
        Exec(
            code=setup_ex.code.copy(),  # shallow copy
            storage=deepcopy(setup_ex.storage),
            balance=setup_ex.balance,
            #
            block=deepcopy(setup_ex.block),
            #
            context=CallContext(message=message),
            callback=None,
            #
            pgm=setup_ex.code[setup_ex.this()],
            pc=0,
            st=State(),
            jumpis={},
            #
            path=path,
            alias=setup_ex.alias.copy(),
            #
            cnts=deepcopy(setup_ex.cnts),
            sha3s=setup_ex.sha3s.copy(),
            storages=setup_ex.storages.copy(),
            balances=setup_ex.balances.copy(),
        )
    )

    normal = 0
    potential = 0
    stuck = []

    #
    # consume the sevm.run() generator
    # (actually triggers path exploration)
    #

    path_id = 0  # default value in case we don't enter the loop body
    submitted_futures = []
    for path_id, ex in enumerate(exs):
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
        if ex.is_panic_of(args.panic_error_codes) or is_global_fail_set(ex.context):
            potential += 1

            if args.verbose >= 1:
                print(f"Found potential path (id: {path_id})")
                panic_code = unbox_int(output.data[4:36].unwrap())
                print(f"Panic(0x{panic_code:02x}) {error_output}")

            # we don't know yet if this will lead to a counterexample
            # so we save the rendered trace here and potentially print it later
            # if a valid counterexample is found
            if args.verbose >= VERBOSITY_TRACE_COUNTEREXAMPLE:
                ctx.traces[path_id] = rendered_trace(ex.context)

            query: SMTQuery = ex.path.to_smt2(args)

            path_ctx = PathContext(
                path_id=path_id,
                ex=ex,
                query=query,
                fun_ctx=ctx,
            )

            def log_future_result(future: Future):
                if e := future.exception():
                    error(f"encountered exception during assertion solving: {e}")

            solve_future = ctx.thread_pool.submit(solve_end_to_end, path_ctx)
            solve_future.add_done_callback(log_future_result)
            submitted_futures.append(solve_future)

            # XXX handle refinement
            # XXX handle timeout

        elif ex.context.is_stuck():
            debug(f"Potential error path (id: {idx+1})")
            res, _, _ = solve(ex.path.to_smt2(args), args)
            if res != unsat:
                stuck.append((idx, ex, ex.context.get_stuck_reason()))
                if args.print_blocked_states:
                    traces[idx] = f"{hexify(ex.path)}\n{rendered_trace(ex.context)}"

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

    num_execs = path_id

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

    if not args.no_status or args.early_exit:
        while True:
            done = sum(fm.done() for fm in submitted_futures)
            total = potential
            if done == total:
                break
            elapsed = timedelta(seconds=int(timer.elapsed()))
            sevm.status.update(f"[{elapsed}] solving queries: {done} / {total}")
            time.sleep(0.1)

    ctx.thread_pool.shutdown(wait=True)

    timer.stop()
    time_info = timer.report(include_subtimers=args.statistics)

    #
    # print test result
    #

    for model in ctx.valid_counterexamples:
        print(red(f"Counterexample: {model}"))

        if args.early_exit:
            break

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

    sevm.status.stop()
    timer.stop()
    time_info = timer.report(include_subtimers=args.statistics)

    # print test result
    print(
        f"{passfail} {funsig} (paths: {num_execs}, {time_info}, "
        f"bounds: [{', '.join([str(x) for x in dyn_params])}])"
    )

    for path_id, _, err in stuck:
        warn_code(INTERNAL_ERROR, f"Encountered {err}")
        if args.print_blocked_states:
            print(f"\nPath #{path_id}")
            print(ctx.traces[path_id], end="")

    (logs, steps) = (sevm.logs, sevm.steps)

    if logs.bounded_loops:
        warn_code(
            LOOP_BOUND,
            f"{funsig}: paths have not been fully explored due to the loop unrolling bound: {args.loop}",
        )
        debug("\n".join(jumpid_str(x) for x in logs.bounded_loops))

    # log steps
    if args.log:
        with open(args.log, "w") as json_file:
            json.dump(steps, json_file)

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

        setup_ex = setup(setup_ctx)
    except Exception as err:
        error(f"{setup_info.sig} failed: {type(err).__name__}: {err}")
        if args.debug:
            traceback.print_exc()

        # reset any remaining solver states from the default context
        setup_solver.reset()

        return []

    test_results = []
    for funsig in ctx.funsigs:
        selector = ctx.method_identifiers[funsig]
        fun_info = FunctionInfo(funsig.split("(")[0], funsig, selector)
        try:
            test_config = with_devdoc(args, funsig, ctx.contract_json)
            solver = mk_solver(test_config)
            debug(f"{test_config.formatted_layers()}")

            test_ctx = FunctionContext(
                args=test_config,
                info=fun_info,
                solver=solver,
                contract_ctx=ctx,
                setup_ex=setup_ex,
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
            solver.reset()

        test_results.append(test_result)

    # reset any remaining solver states from the default context
    setup_solver.reset()

    return test_results


def parse_unsat_core(output) -> list[str] | None:
    # parsing example:
    #   unsat
    #   (error "the context is unsatisfiable")  # <-- this line is optional
    #   (<41702> <37030> <36248> <47880>)
    # result:
    #   [41702, 37030, 36248, 47880]
    pattern = r"unsat\s*(\(\s*error\s+[^)]*\)\s*)?\(\s*((<[0-9]+>\s*)*)\)"
    match = re.search(pattern, output)
    if match:
        result = [re.sub(r"<([0-9]+)>", r"\1", name) for name in match.group(2).split()]
        return result
    else:
        warn(f"error in parsing unsat core: {output}")
        return None


def dump(
    path_ctx: PathContext,
) -> tuple[CheckSatResult, PotentialModel | None, list | None]:
    args = path_ctx.fun_ctx.args
    query = path_ctx.query
    dump_filename = path_ctx.dump_filename

    if args.verbose >= 1:
        debug(f"Writing SMT query to {dump_filename}")

    # for each implication assertion, `(assert (=> |id| c))`, in query.smtlib,
    # generate a corresponding named assertion, `(assert (! |id| :named <id>))`.
    # see `svem.Path.to_smt2()` for more details.
    if args.cache_solver:
        named_assertions = "".join(
            [
                f"(assert (! |{assert_id}| :named <{assert_id}>))\n"
                for assert_id in query.assertions
            ]
        )

        with open(dump_filename, "w") as f:
            f.write("(set-option :produce-unsat-cores true)\n")
            f.write("(set-logic QF_AUFBV)\n")
            f.write(query.smtlib)
            f.write(named_assertions)
            f.write("(check-sat)\n")
            f.write("(get-model)\n")
            f.write("(get-unsat-core)\n")

    else:
        with open(dump_filename, "w") as f:
            f.write("(set-logic QF_AUFBV)\n")
            f.write(query.smtlib)
            f.write("(check-sat)\n")
            f.write("(get-model)\n")


def is_model_valid(solver_stdout: str) -> bool:
    # TODO: evaluate the path condition against the given model after excluding f_evm_* symbols,
    #       since the f_evm_* symbols may still appear in valid models.

    return "f_evm_" not in solver_stdout


def solve_low_level(path_ctx: PathContext) -> SolverOutput:
    """Invokes an external solver process to solve the given query.

    Can raise TimeoutError or some Exception raised during execution"""

    fun_ctx, smt2_filename = path_ctx.fun_ctx, path_ctx.dump_filename
    args = fun_ctx.args

    # make sure the smt2 file has been written
    dump(path_ctx)

    if args.verbose >= 1:
        print("  Checking with external solver process")
        print(f"    {args.solver_command} {smt2_filename} > {smt2_filename}.out")

    # XXX fix timeout

    # solver_timeout_assertion == 0 means no timeout,
    # which translates to timeout_seconds=None for subprocess.run
    # timeout_seconds = None
    # if timeout_millis := args.solver_timeout_assertion:
    #     timeout_seconds = timeout_millis / 1000

    cmd = args.solver_command.split() + [smt2_filename]
    future = PopenFuture(cmd, metadata={"path_ctx": path_ctx})

    # XXX avoiding callbacks now
    # future.add_done_callback(solver_callback)

    fun_ctx.solver_executor.submit(future)

    # block until the external solver returns, times out, is interrupted, fails, etc.
    stdout, stderr, returncode = future.result()

    # save solver stdout to file
    with open(f"{smt2_filename}.out", "w") as f:
        f.write(stdout)

    # save solver stderr to file (only if there is an error)
    if stderr:
        with open(f"{smt2_filename}.err", "w") as f:
            f.write(stderr)

    return SolverOutput.from_result(stdout, stderr, returncode, path_ctx)


# XXX used to be gen_model_from_sexpr
def solve_end_to_end(ctx: PathContext) -> None:
    """Synchronously resolves a query in a given context, which may result in 0, 1 or multiple solver invocations.

    - may result in 0 invocations if the query contains a known unsat core (hence the need for the context)
    - may result in exactly 1 invocation if the query is unsat, or sat with a valid model
    - may result in multiple invocations if the query is sat and the model is invalid (needs refinement)

    If this produces a model, it _should_ be valid.
    """
    fun_ctx, path_id, query = ctx.fun_ctx, ctx.path_id, ctx.query
    args, unsat_cores = fun_ctx.args, fun_ctx.unsat_cores

    verbose = print if args.verbose >= 1 else lambda *args, **kwargs: None
    verbose(f"Checking path condition {path_id=}")

    # if the query contains an unsat-core, it is unsat; no need to run the solver
    if check_unsat_cores(query, unsat_cores):
        verbose("  Already proven unsat")
        return SolverOutput(unsat, path_id)

    solver_output = solve_low_level(ctx)
    result, model = solver_output.result, solver_output.model

    # if the ctx is already refined, we don't need to solve again
    if result == sat and not model.is_valid and not ctx.is_refined:
        verbose("  Checking again with refinement")

        refined_ctx = ctx.refine()

        if refined_ctx.query.smtlib != query.smtlib:
            # recurse with the refined query
            return solve_end_to_end(refined_ctx)
        else:
            verbose("    Refinement did not change the query, no need to solve again")

    #
    # we are done solving, process and triage the result
    #

    # retrieve cached exec and clear the cache entry
    exec = fun_ctx.exec_cache.pop(path_id, None)

    if args.verbose >= VERBOSITY_TRACE_COUNTEREXAMPLE:
        id_str = f" #{path_id}" if args.verbose >= VERBOSITY_TRACE_PATHS else ""
        print(f"Trace{id_str}:")
        print(fun_ctx.traces[path_id], end="")

    if args.print_failed_states:
        print(f"# {path_id}")
        print(exec)

    if fun_ctx.solver_executor.is_shutdown():
        # if the thread pool is in the process of shutting down,
        # we want to stop processing remaining models/timeouts/errors, etc.
        return

    if result == unsat:
        if solver_output.unsat_core:
            fun_ctx.unsat_cores.append(solver_output.unsat_core)
        return

    # model could be an empty dict here, so compare to None explicitly
    if model is None:
        warn_code(COUNTEREXAMPLE_UNKNOWN, f"Counterexample: {result}")
        return

    if model.is_valid:
        # we don't print the model here because this may be called from multiple threads
        fun_ctx.valid_counterexamples.append(model)

        # we have a valid counterexample, so we are eligible for early exit
        if args.early_exit:
            fun_ctx.solver_executor.shutdown(wait=False)
    else:
        # XXX avoid printing here
        warn_str = f"Counterexample (potentially invalid): {model}"
        warn_code(COUNTEREXAMPLE_INVALID, warn_str)
        fun_ctx.invalid_counterexamples.append(model)


def check_unsat_cores(query: SMTQuery, unsat_cores: list[list]) -> bool:
    # return true if the given query contains any given unsat core
    for unsat_core in unsat_cores:
        if all(core in query.assertions for core in unsat_core):
            return True
    return False


def refine(query: SMTQuery) -> SMTQuery:
    smtlib = query.smtlib

    # replace uninterpreted abstraction with actual symbols for assertion solving
    smtlib = re.sub(
        r"\(declare-fun f_evm_(bvmul)_([0-9]+) \(\(_ BitVec \2\) \(_ BitVec \2\)\) \(_ BitVec \2\)\)",
        r"(define-fun f_evm_\1_\2 ((x (_ BitVec \2)) (y (_ BitVec \2))) (_ BitVec \2) (\1 x y))",
        smtlib,
    )

    # replace `(f_evm_bvudiv_N x y)` with `(ite (= y (_ bv0 N)) (_ bv0 N) (bvudiv x y))`
    # similarly for bvurem, bvsdiv, and bvsrem
    # NOTE: (bvudiv x (_ bv0 N)) is *defined* to (bvneg (_ bv1 N)); while (div x 0) is undefined
    smtlib = re.sub(
        r"\(declare-fun f_evm_(bvudiv|bvurem|bvsdiv|bvsrem)_([0-9]+) \(\(_ BitVec \2\) \(_ BitVec \2\)\) \(_ BitVec \2\)\)",
        r"(define-fun f_evm_\1_\2 ((x (_ BitVec \2)) (y (_ BitVec \2))) (_ BitVec \2) (ite (= y (_ bv0 \2)) (_ bv0 \2) (\1 x y)))",
        smtlib,
    )

    return SMTQuery(smtlib, query.assertions)


def get_contract_type(
    ast_nodes: list, contract_name: str
) -> tuple[str | None, str | None]:
    for node in ast_nodes:
        if node["nodeType"] == "ContractDefinition" and node["name"] == contract_name:
            abstract = "abstract " if node.get("abstract") else ""
            contract_type = abstract + node["contractKind"]
            natspec = node.get("documentation")
            return contract_type, natspec

    return None, None


def parse_build_out(args: HalmosConfig) -> dict:
    result = {}  # compiler version -> source filename -> contract name -> (json, type)

    out_path = os.path.join(args.root, args.forge_build_out)
    if not os.path.exists(out_path):
        raise FileNotFoundError(
            f"The build output directory `{out_path}` does not exist"
        )

    for sol_dirname in os.listdir(out_path):  # for each source filename
        if not sol_dirname.endswith(".sol"):
            continue

        sol_path = os.path.join(out_path, sol_dirname)
        if not os.path.isdir(sol_path):
            continue

        for json_filename in os.listdir(sol_path):  # for each contract name
            try:
                if not json_filename.endswith(".json"):
                    continue
                if json_filename.startswith("."):
                    continue

                json_path = os.path.join(sol_path, json_filename)
                with open(json_path, encoding="utf8") as f:
                    json_out = json.load(f)

                # cut off compiler version number as well
                contract_name = json_filename.split(".")[0]
                ast_nodes = json_out["ast"]["nodes"]
                contract_type, natspec = get_contract_type(ast_nodes, contract_name)

                # can happen to solidity files for multiple reasons:
                # - import only (like console2.log)
                # - defines only structs or enums
                # - defines only free functions
                # - ...
                if contract_type is None:
                    debug(f"Skipped {json_filename}, no contract definition found")
                    continue

                compiler_version = json_out["metadata"]["compiler"]["version"]
                result.setdefault(compiler_version, {})
                result[compiler_version].setdefault(sol_dirname, {})
                contract_map = result[compiler_version][sol_dirname]

                if contract_name in contract_map:
                    raise ValueError(
                        "duplicate contract names in the same file",
                        contract_name,
                        sol_dirname,
                    )

                contract_map[contract_name] = (json_out, contract_type, natspec)
                parse_symbols(args, contract_map, contract_name)

            except Exception as err:
                warn_code(
                    PARSING_ERROR,
                    f"Skipped {json_filename} due to parsing failure: {type(err).__name__}: {err}",
                )
                if args.debug:
                    traceback.print_exc()
                continue

    return result


def parse_symbols(args: HalmosConfig, contract_map: dict, contract_name: str) -> None:
    try:
        json_out = contract_map[contract_name][0]
        bytecode = json_out["bytecode"]["object"]
        contract_mapping_info = Mapper().get_or_create(contract_name)
        contract_mapping_info.bytecode = bytecode

        Mapper().parse_ast(json_out["ast"])

    except Exception:
        debug(f"error parsing symbols for contract {contract_name}")
        debug(traceback.format_exc())

        # we parse symbols as best effort, don't propagate exceptions
        pass


def parse_devdoc(funsig: str, contract_json: dict) -> str | None:
    try:
        return contract_json["metadata"]["output"]["devdoc"]["methods"][funsig][
            "custom:halmos"
        ]
    except KeyError:
        return None


def parse_natspec(natspec: dict) -> str:
    # This parsing scheme is designed to handle:
    #
    # - multiline tags:
    #   /// @custom:halmos --x
    #   ///                --y
    #
    # - multiple tags:
    #   /// @custom:halmos --x
    #   /// @custom:halmos --y
    #
    # - tags that start in the middle of line:
    #   /// blah blah @custom:halmos --x
    #   /// --y
    #
    # In all the above examples, this scheme returns "--x (whitespaces) --y"
    isHalmosTag = False
    result = ""
    for item in re.split(r"(@\S+)", natspec.get("text", "")):
        if item == "@custom:halmos":
            isHalmosTag = True
        elif re.match(r"^@\S", item):
            isHalmosTag = False
        elif isHalmosTag:
            result += item
    return result.strip()


def import_libs(build_out_map: dict, hexcode: str, linkReferences: dict) -> dict:
    libs = {}

    for filepath in linkReferences:
        file_name = filepath.split("/")[-1]

        for lib_name in linkReferences[filepath]:
            (lib_json, _, _) = build_out_map[file_name][lib_name]
            lib_hexcode = lib_json["deployedBytecode"]["object"]

            # in bytes, multiply indices by 2 and offset 0x
            placeholder_index = linkReferences[filepath][lib_name][0]["start"] * 2 + 2
            placeholder = hexcode[placeholder_index : placeholder_index + 40]

            libs[f"{filepath}:{lib_name}"] = {
                "placeholder": placeholder,
                "hexcode": lib_hexcode,
            }

    return libs


def build_output_iterator(build_out: dict):
    for compiler_version in sorted(build_out):
        build_out_map = build_out[compiler_version]
        for filename in sorted(build_out_map):
            for contract_name in sorted(build_out_map[filename]):
                yield (build_out_map, filename, contract_name)


def contract_regex(args):
    if args.contract:
        return f"^{args.contract}$"
    else:
        return args.match_contract


def test_regex(args):
    if args.match_test.startswith("^"):
        return args.match_test
    else:
        return f"^{args.function}.*{args.match_test}"


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

    for build_out_map, filename, contract_name in build_output_iterator(build_out):
        if not re.search(contract_regex(args), contract_name):
            continue

        (contract_json, contract_type, natspec) = build_out_map[filename][contract_name]
        if contract_type != "contract":
            continue

        methodIdentifiers = contract_json["methodIdentifiers"]
        funsigs = [f for f in methodIdentifiers if re.search(test_regex(args), f)]
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
        num_passed = sum(r.exitcode == 0 for r in test_results)
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
    return _main().exitcode


# entrypoint for `python -m halmos`
if __name__ == "__main__":
    sys.exit(main())
