# SPDX-License-Identifier: AGPL-3.0

import gc
import io
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
from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import asdict, dataclass
from datetime import timedelta
from enum import Enum
from importlib import metadata

from rich.status import Status
from z3 import (
    Z3_OP_CONCAT,
    BitVec,
    BitVecNumRef,
    BitVecRef,
    Bool,
    CheckSatResult,
    Context,
    ModelRef,
    Solver,
    is_app,
    is_bv,
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
    EventLog,
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
from .utils import (
    NamedTimer,
    address,
    byte_length,
    color_error,
    con,
    create_solver,
    cyan,
    green,
    hexify,
    indent_text,
    red,
    stringify,
    unbox_int,
    yellow,
)

StrModel = dict[str, str]
AnyModel = StrModel | str

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


def mk_solver(args: HalmosConfig, logic="QF_AUFBV", ctx=None, assertion=False):
    timeout = (
        args.solver_timeout_assertion if assertion else args.solver_timeout_branching
    )
    return create_solver(logic, ctx, timeout, args.solver_max_memory)


def rendered_initcode(context: CallContext) -> str:
    message = context.message
    data = message.data

    initcode_str = ""
    args_str = ""

    if (
        isinstance(data, BitVecRef)
        and is_app(data)
        and data.decl().kind() == Z3_OP_CONCAT
    ):
        children = [arg for arg in data.children()]
        if isinstance(children[0], BitVecNumRef):
            initcode_str = hex(children[0].as_long())
            args_str = ", ".join(map(str, children[1:]))
    else:
        initcode_str = hexify(data)

    return f"{initcode_str}({cyan(args_str)})"


def render_output(context: CallContext, file=sys.stdout) -> None:
    output = context.output
    returndata_str = "0x"
    failed = output.error is not None

    if not failed and context.is_stuck():
        return

    data = output.data
    if data is not None:
        is_create = context.message.is_create()
        if hasattr(data, "unwrap"):
            data = data.unwrap()

        returndata_str = (
            f"<{byte_length(data)} bytes of code>"
            if (is_create and not failed)
            else hexify(data)
        )

    ret_scheme = context.output.return_scheme
    ret_scheme_str = f"{cyan(mnemonic(ret_scheme))} " if ret_scheme is not None else ""
    error_str = f" (error: {repr(output.error)})" if failed else ""

    color = red if failed else green
    indent = context.depth * "    "
    print(
        f"{indent}{color('↩ ')}{ret_scheme_str}{color(returndata_str)}{color(error_str)}",
        file=file,
    )


def rendered_log(log: EventLog) -> str:
    opcode_str = f"LOG{len(log.topics)}"
    topics = [
        f"{cyan(f'topic{i}')}={hexify(topic)}" for i, topic in enumerate(log.topics)
    ]
    data_str = f"{cyan('data')}={hexify(log.data)}"
    args_str = ", ".join(topics + [data_str])

    return f"{opcode_str}({args_str})"


def rendered_trace(context: CallContext) -> str:
    with io.StringIO() as output:
        render_trace(context, file=output)
        return output.getvalue()


def rendered_calldata(calldata: ByteVec, contract_name: str | None = None) -> str:
    if not calldata:
        return "0x"

    if len(calldata) < 4:
        return hexify(calldata)

    if len(calldata) == 4:
        return f"{hexify(calldata.unwrap(), contract_name)}()"

    selector = calldata[:4].unwrap()
    args = calldata[4:].unwrap()
    return f"{hexify(selector, contract_name)}({hexify(args)})"


def render_trace(context: CallContext, file=sys.stdout) -> None:
    message = context.message
    addr = unbox_int(message.target)
    addr_str = str(addr) if is_bv(addr) else hex(addr)
    # check if we have a contract name for this address in our deployment mapper
    addr_str = DeployAddressMapper().get_deployed_contract(addr_str)

    value = unbox_int(message.value)
    value_str = f" (value: {value})" if is_bv(value) or value > 0 else ""

    call_scheme_str = f"{cyan(mnemonic(message.call_scheme))} "
    indent = context.depth * "    "

    if message.is_create():
        # TODO: select verbosity level to render full initcode
        # initcode_str = rendered_initcode(context)

        try:
            if context.output.error is None:
                target = hex(int(str(message.target)))
                bytecode = context.output.data.unwrap().hex()
                contract_name = Mapper().get_by_bytecode(bytecode).contract_name

                DeployAddressMapper().add_deployed_contract(target, contract_name)
                addr_str = contract_name
        except Exception:
            # TODO: print in debug mode
            ...

        initcode_str = f"<{byte_length(message.data)} bytes of initcode>"
        print(
            f"{indent}{call_scheme_str}{addr_str}::{initcode_str}{value_str}", file=file
        )

    else:
        calldata = rendered_calldata(message.data, addr_str)
        call_str = f"{addr_str}::{calldata}"
        static_str = yellow(" [static]") if message.is_static else ""
        print(f"{indent}{call_scheme_str}{call_str}{static_str}{value_str}", file=file)

    log_indent = (context.depth + 1) * "    "
    for trace_element in context.trace:
        if isinstance(trace_element, CallContext):
            render_trace(trace_element, file=file)
        elif isinstance(trace_element, EventLog):
            print(f"{log_indent}{rendered_log(trace_element)}", file=file)
        else:
            raise HalmosException(f"unexpected trace element: {trace_element}")

    render_output(context, file=file)

    if context.depth == 1:
        print(file=file)


def deploy_test(
    creation_hexcode: str,
    deployed_hexcode: str,
    sevm: SEVM,
    args: HalmosConfig,
    libs: dict,
    solver: Solver,
) -> Exec:
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
        path=Path(solver),
    )

    # deploy libraries and resolve library placeholders in hexcode
    (creation_hexcode, deployed_hexcode) = ex.resolve_libs(
        creation_hexcode, deployed_hexcode, libs
    )

    # test contract creation bytecode
    creation_bytecode = Contract.from_hexcode(creation_hexcode)
    ex.pgm = creation_bytecode

    # create test contract
    exs = list(sevm.run(ex))

    # sanity check
    if len(exs) != 1:
        raise ValueError(f"constructor: # of paths: {len(exs)}")

    ex = exs[0]

    if args.verbose >= VERBOSITY_TRACE_CONSTRUCTOR:
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


def setup(
    creation_hexcode: str,
    deployed_hexcode: str,
    abi: dict,
    setup_info: FunctionInfo,
    args: HalmosConfig,
    libs: dict,
    solver: Solver,
) -> Exec:
    setup_timer = NamedTimer("setup")
    setup_timer.create_subtimer("decode")

    sevm = SEVM(args)
    setup_ex = deploy_test(creation_hexcode, deployed_hexcode, sevm, args, libs, solver)

    setup_timer.create_subtimer("run")

    setup_sig = setup_info.sig
    if setup_sig:
        # TODO: dyn_params may need to be passed to mk_calldata in run()
        calldata, dyn_params = mk_calldata(abi, setup_info, args)
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
        setup_exs_no_error = []

        for idx, setup_ex in enumerate(setup_exs_all):
            if args.verbose >= VERBOSITY_TRACE_SETUP:
                print(f"{setup_sig} trace #{idx+1}:")
                render_trace(setup_ex.context)

            if not setup_ex.context.output.error:
                setup_exs_no_error.append((setup_ex, setup_ex.path.to_smt2(args)))

            else:
                opcode = setup_ex.current_opcode()
                if opcode not in [EVM.REVERT, EVM.INVALID]:
                    warn_code(
                        INTERNAL_ERROR,
                        f"Warning: {setup_sig} execution encountered an issue at {mnemonic(opcode)}: {error}",
                    )

                # only render the trace if we didn't already do it
                if (
                    args.verbose < VERBOSITY_TRACE_SETUP
                    and args.verbose >= VERBOSITY_TRACE_COUNTEREXAMPLE
                ):
                    print(f"{setup_sig} trace:")
                    render_trace(setup_ex.context)

        setup_exs = []

        if len(setup_exs_no_error) > 1:
            for setup_ex, query in setup_exs_no_error:
                res, _, _ = solve(query, args)
                if res != unsat:
                    setup_exs.append(setup_ex)
                    if len(setup_exs) > 1:
                        break

        elif len(setup_exs_no_error) == 1:
            setup_exs.append(setup_exs_no_error[0][0])

        if len(setup_exs) == 0:
            raise HalmosException(f"No successful path found in {setup_sig}")

        if len(setup_exs) > 1:
            debug("\n".join(map(str, setup_exs)))

            raise HalmosException(f"Multiple paths were found in {setup_sig}")

        setup_ex = setup_exs[0]

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


@dataclass
class PotentialModel:
    model: AnyModel
    is_valid: bool

    def __init__(self, model: ModelRef | str, args: HalmosConfig) -> None:
        # convert model into string to avoid pickling errors for z3 (ctypes) objects containing pointers
        self.model = (
            to_str_model(model, args.print_full_model)
            if isinstance(model, ModelRef)
            else model
        )
        self.is_valid = is_model_valid(model)

    def __str__(self) -> str:
        # expected to be a filename
        if isinstance(self.model, str):
            return f"see {self.model}"

        formatted = [f"\n    {decl} = {val}" for decl, val in self.model.items()]
        return "".join(sorted(formatted)) if formatted else "∅"


@dataclass(frozen=True)
class ModelWithContext:
    # can be a filename containing the model or a dict with variable assignments
    model: PotentialModel | None
    index: int
    result: CheckSatResult
    unsat_core: list | None


@dataclass(frozen=True)
class TestResult:
    name: str  # test function name
    exitcode: int
    num_models: int = None
    models: list[ModelWithContext] = None
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


def is_global_fail_set(context: CallContext) -> bool:
    hevm_fail = isinstance(context.output.error, FailCheatcode)
    return hevm_fail or any(is_global_fail_set(x) for x in context.subcalls())


def run(
    setup_ex: Exec,
    abi: dict,
    fun_info: FunctionInfo,
    args: HalmosConfig,
    solver: Solver,
) -> TestResult:
    funname, funsig = fun_info.name, fun_info.sig
    if args.verbose >= 1:
        print(f"Executing {funname}")

    dump_dirname = f"/tmp/{funname}-{uuid.uuid4().hex}"

    #
    # calldata
    #

    sevm = SEVM(args)
    path = Path(solver)
    path.extend_path(setup_ex.path)

    cd, dyn_params = mk_calldata(abi, fun_info, args)
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

    (logs, steps) = (sevm.logs, sevm.steps)

    # check assertion violations
    normal = 0
    models: list[ModelWithContext] = []
    stuck = []

    thread_pool = ThreadPoolExecutor(max_workers=args.solver_threads)
    result_exs = []
    future_models = []
    counterexamples = []
    unsat_cores = []
    traces = {}

    def future_callback(future_model):
        m = future_model.result()
        models.append(m)

        model, index, result = m.model, m.index, m.result
        if result == unsat:
            if m.unsat_core:
                unsat_cores.append(m.unsat_core)
            return

        # model could be an empty dict here
        if model is not None:
            if model.is_valid:
                print(red(f"Counterexample: {model}"))
                counterexamples.append(model)
            else:
                warn_code(
                    COUNTEREXAMPLE_INVALID,
                    f"Counterexample (potentially invalid): {model}",
                )
                counterexamples.append(model)
        else:
            warn_code(COUNTEREXAMPLE_UNKNOWN, f"Counterexample: {result}")

        if args.print_failed_states:
            print(f"# {idx+1}")
            print(result_exs[index])

        if args.verbose >= VERBOSITY_TRACE_COUNTEREXAMPLE:
            print(
                f"Trace #{idx+1}:"
                if args.verbose == VERBOSITY_TRACE_PATHS
                else "Trace:"
            )
            print(traces[index], end="")

    for idx, ex in enumerate(exs):
        result_exs.append(ex)

        if args.verbose >= VERBOSITY_TRACE_PATHS:
            print(f"Path #{idx+1}:")
            print(indent_text(hexify(ex.path)))

            print("\nTrace:")
            render_trace(ex.context)

        output = ex.context.output
        error_output = output.error
        if ex.is_panic_of(args.panic_error_codes) or is_global_fail_set(ex.context):
            if args.verbose >= 1:
                print(f"Found potential path (id: {idx+1})")
                panic_code = unbox_int(output.data[4:36].unwrap())
                print(f"Panic(0x{panic_code:02x}) {error_output}")

            if args.verbose >= VERBOSITY_TRACE_COUNTEREXAMPLE:
                traces[idx] = rendered_trace(ex.context)

            query = ex.path.to_smt2(args)

            future_model = thread_pool.submit(
                gen_model_from_sexpr,
                GenModelArgs(args, idx, query, unsat_cores, dump_dirname),
            )
            future_model.add_done_callback(future_callback)
            future_models.append(future_model)

        elif ex.context.is_stuck():
            stuck.append((idx, ex, ex.context.get_stuck_reason()))
            if args.print_blocked_states:
                traces[idx] = f"{hexify(ex.path)}\n{rendered_trace(ex.context)}"

        elif not error_output:
            if args.print_success_states:
                print(f"# {idx+1}")
                print(ex)
            normal += 1

        # 0 width is unlimited
        if args.width and len(result_exs) >= args.width:
            break

    timer.create_subtimer("models")

    if len(future_models) > 0 and args.verbose >= 1:
        print(
            f"# of potential paths involving assertion violations: {len(future_models)} / {len(result_exs)}  (--solver-threads {args.solver_threads})"
        )

    # display assertion solving progress
    if not args.no_status or args.early_exit:
        with Status("") as status:
            while True:
                if args.early_exit and len(counterexamples) > 0:
                    break
                done = sum(fm.done() for fm in future_models)
                total = len(future_models)
                if done == total:
                    break
                elapsed = timedelta(seconds=int(timer.elapsed()))
                status.update(f"[{elapsed}] solving queries: {done} / {total}")
                time.sleep(0.1)

    if args.early_exit:
        thread_pool.shutdown(wait=False, cancel_futures=True)
    else:
        thread_pool.shutdown(wait=True)

    counter = Counter(str(m.result) for m in models)
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

    # print result
    print(
        f"{passfail} {funsig} (paths: {len(result_exs)}, {time_info}, bounds: [{', '.join([str(x) for x in dyn_params])}])"
    )

    for idx, _, err in stuck:
        warn_code(INTERNAL_ERROR, f"Encountered {err}")
        if args.print_blocked_states:
            print(f"\nPath #{idx+1}")
            print(traces[idx], end="")

    if logs.bounded_loops:
        warn_code(
            LOOP_BOUND,
            f"{funsig}: paths have not been fully explored due to the loop unrolling bound: {args.loop}",
        )
        debug("\n".join(jumpid_str(x) for x in logs.bounded_loops))

    # print post-states
    if args.print_states:
        for idx, ex in enumerate(result_exs):
            print(f"# {idx+1} / {len(result_exs)}")
            print(ex)

    # log steps
    if args.log:
        with open(args.log, "w") as json_file:
            json.dump(steps, json_file)

    # return test result
    if args.minimal_json_output:
        return TestResult(funsig, exitcode, len(counterexamples))
    else:
        return TestResult(
            funsig,
            exitcode,
            len(counterexamples),
            counterexamples,
            (len(result_exs), normal, len(stuck)),
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


@dataclass(frozen=True)
class RunArgs:
    # signatures of test functions to run
    funsigs: list[str]

    # code of the current contract
    creation_hexcode: str
    deployed_hexcode: str

    abi: dict
    methodIdentifiers: dict[str, str]

    args: HalmosConfig
    contract_json: dict
    libs: dict

    build_out_map: dict


def run_sequential(run_args: RunArgs) -> list[TestResult]:
    BuildOut().set_build_out(run_args.build_out_map)

    args = run_args.args
    setup_info = extract_setup(run_args.methodIdentifiers)

    try:
        setup_config = with_devdoc(args, setup_info.sig, run_args.contract_json)
        setup_solver = mk_solver(setup_config)
        setup_ex = setup(
            run_args.creation_hexcode,
            run_args.deployed_hexcode,
            run_args.abi,
            setup_info,
            setup_config,
            run_args.libs,
            setup_solver,
        )
    except Exception as err:
        error(f"Error: {setup_info.sig} failed: {type(err).__name__}: {err}")
        if args.debug:
            traceback.print_exc()
        # reset any remaining solver states from the default context
        setup_solver.reset()
        return []

    test_results = []
    for funsig in run_args.funsigs:
        fun_info = FunctionInfo(
            funsig.split("(")[0], funsig, run_args.methodIdentifiers[funsig]
        )
        try:
            test_config = with_devdoc(args, funsig, run_args.contract_json)
            solver = mk_solver(test_config)
            debug(f"{test_config.formatted_layers()}")
            test_result = run(setup_ex, run_args.abi, fun_info, test_config, solver)
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


@dataclass(frozen=True)
class GenModelArgs:
    args: HalmosConfig
    idx: int
    sexpr: SMTQuery
    known_unsat_cores: list[list]
    dump_dirname: str | None = None


def parse_unsat_core(output) -> list | None:
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


def solve(
    query: SMTQuery, args: HalmosConfig, dump_filename: str | None = None
) -> tuple[CheckSatResult, PotentialModel | None, list | None]:
    if args.dump_smt_queries or args.solver_command:
        if not dump_filename:
            dump_filename = f"/tmp/{uuid.uuid4().hex}.smt2"

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
            if args.verbose >= 1:
                debug(f"Writing SMT query to {dump_filename}")
            if args.cache_solver:
                f.write("(set-option :produce-unsat-cores true)\n")
            f.write("(set-logic QF_AUFBV)\n")
            f.write(query.smtlib)
            if args.cache_solver:
                f.write(named_assertions)
            f.write("(check-sat)\n")
            f.write("(get-model)\n")
            if args.cache_solver:
                f.write("(get-unsat-core)\n")

    if args.solver_command:
        if args.verbose >= 1:
            debug("  Checking with external solver process")
            debug(f"    {args.solver_command} {dump_filename} >{dump_filename}.out")

        # solver_timeout_assertion == 0 means no timeout,
        # which translates to timeout_seconds=None for subprocess.run
        timeout_seconds = None
        if timeout_millis := args.solver_timeout_assertion:
            timeout_seconds = timeout_millis / 1000

        cmd = args.solver_command.split() + [dump_filename]
        try:
            res_str = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout_seconds
            ).stdout.strip()
            res_str_head = res_str.split("\n", 1)[0]

            with open(f"{dump_filename}.out", "w") as f:
                f.write(res_str)

            if args.verbose >= 1:
                debug(f"    {res_str_head}")

            if res_str_head == "unsat":
                unsat_core = parse_unsat_core(res_str) if args.cache_solver else None
                return unsat, None, unsat_core
            elif res_str_head == "sat":
                return sat, PotentialModel(f"{dump_filename}.out", args), None
            else:
                return unknown, None, None
        except subprocess.TimeoutExpired:
            return unknown, None, None

    else:
        ctx = Context()
        solver = mk_solver(args, ctx=ctx, assertion=True)
        solver.from_string(query.smtlib)
        if args.cache_solver:
            solver.set(unsat_core=True)
            ids = [Bool(f"{x}", ctx) for x in query.assertions]
            result = solver.check(*ids)
        else:
            result = solver.check()
        model = PotentialModel(solver.model(), args) if result == sat else None
        unsat_core = (
            [str(core) for core in solver.unsat_core()]
            if args.cache_solver and result == unsat
            else None
        )
        solver.reset()
        return result, model, unsat_core


def check_unsat_cores(query, unsat_cores) -> bool:
    # return true if the given query contains any given unsat core
    for unsat_core in unsat_cores:
        if all(core in query.assertions for core in unsat_core):
            return True
    return False


def gen_model_from_sexpr(fn_args: GenModelArgs) -> ModelWithContext:
    args, idx, sexpr = fn_args.args, fn_args.idx, fn_args.sexpr

    dump_dirname = fn_args.dump_dirname
    dump_filename = f"{dump_dirname}/{idx+1}.smt2"
    should_dump = args.dump_smt_queries or args.solver_command
    if should_dump and not os.path.isdir(dump_dirname):
        os.makedirs(dump_dirname)
        print(f"Generating SMT queries in {dump_dirname}")

    if args.verbose >= 1:
        print(f"Checking path condition (path id: {idx+1})")

    if check_unsat_cores(sexpr, fn_args.known_unsat_cores):
        # if the given query contains an unsat-core, it is unsat; no need to run the solver.
        if args.verbose >= 1:
            print("  Already proven unsat")
        return package_result(None, idx, unsat, None, args)

    res, model, unsat_core = solve(sexpr, args, dump_filename)

    if res == sat and not model.is_valid:
        if args.verbose >= 1:
            print("  Checking again with refinement")

        refined_filename = dump_filename.replace(".smt2", ".refined.smt2")
        res, model, unsat_core = solve(refine(sexpr), args, refined_filename)

    return package_result(model, idx, res, unsat_core, args)


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


def package_result(
    model: PotentialModel | None,
    idx: int,
    result: CheckSatResult,
    unsat_core: list | None,
    args: HalmosConfig,
) -> ModelWithContext:
    if result == unsat:
        if args.verbose >= 1:
            print(f"  Invalid path; ignored (path id: {idx+1})")
        return ModelWithContext(None, idx, result, unsat_core)

    if result == sat:
        if args.verbose >= 1:
            print(f"  Valid path; counterexample generated (path id: {idx+1})")
        return ModelWithContext(model, idx, result, None)

    else:
        if args.verbose >= 1:
            print(f"  Timeout (path id: {idx+1})")
        return ModelWithContext(None, idx, result, None)


def is_model_valid(model: ModelRef | str) -> bool:
    # TODO: evaluate the path condition against the given model after excluding f_evm_* symbols,
    #       since the f_evm_* symbols may still appear in valid models.

    # model is a filename, containing solver output
    if isinstance(model, str):
        with open(model) as f:
            for line in f:
                if "f_evm_" in line:
                    return False
        return True

    # z3 model object
    else:
        return all(not str(decl).startswith("f_evm_") for decl in model)


def to_str_model(model: ModelRef, print_full_model: bool) -> StrModel:
    def select(var):
        name = str(var)
        return name.startswith("p_") or name.startswith("halmos_")

    select_model = filter(select, model) if not print_full_model else model
    return {str(decl): stringify(str(decl), model[decl]) for decl in select_model}


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
        run_args = RunArgs(
            funsigs,
            creation_hexcode,
            deployed_hexcode,
            abi,
            methodIdentifiers,
            contract_args,
            contract_json,
            libs,
            build_out_map,
        )

        test_results = run_sequential(run_args)

        num_passed = sum(r.exitcode == 0 for r in test_results)
        num_failed = num_found - num_passed

        print(
            f"Symbolic test result: {num_passed} passed; "
            f"{num_failed} failed; {contract_timer.report()}"
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
            "Error: No tests with"
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
