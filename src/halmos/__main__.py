# SPDX-License-Identifier: AGPL-3.0

import json
import os
import re
import signal
import subprocess
import sys
import time
import traceback
import uuid
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import asdict, dataclass
from enum import Enum
from importlib import metadata

from .bytevec import ByteVec
from .calldata import Calldata
from .config import Config as HalmosConfig
from .config import arg_parser, default_config, resolve_config_files, toml_parser
from .mapper import DeployAddressMapper, Mapper
from .sevm import *
from .utils import (
    NamedTimer,
    create_solver,
    cyan,
    error,
    green,
    hexify,
    indent_text,
    info,
    red,
    stringify,
    yellow,
)
from .warnings import *

StrModel = Dict[str, str]
AnyModel = UnionType[Model, StrModel]

# Python version >=3.8.14, >=3.9.14, >=3.10.7, or >=3.11
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(0)

# we need to be able to process at least the max message depth (1024)
sys.setrecursionlimit(1024 * 4)

# sometimes defaults to cp1252 on Windows, which can cause UnicodeEncodeError
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")

# Panic(1)
# bytes4(keccak256("Panic(uint256)")) + bytes32(1)
ASSERT_FAIL = 0x4E487B710000000000000000000000000000000000000000000000000000000000000001

VERBOSITY_TRACE_COUNTEREXAMPLE = 2
VERBOSITY_TRACE_SETUP = 3
VERBOSITY_TRACE_PATHS = 4
VERBOSITY_TRACE_CONSTRUCTOR = 5


def with_devdoc(args: HalmosConfig, fn_sig: str, contract_json: Dict) -> HalmosConfig:
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


@dataclass(frozen=True)
class FunctionInfo:
    name: Optional[str] = None
    sig: Optional[str] = None
    selector: Optional[str] = None


def str_abi(item: Dict) -> str:
    def str_tuple(args: List) -> str:
        ret = []
        for arg in args:
            typ = arg["type"]
            match = re.search(r"^tuple((\[[0-9]*\])*)$", typ)
            if match:
                ret.append(str_tuple(arg["components"]) + match.group(1))
            else:
                ret.append(typ)
        return "(" + ",".join(ret) + ")"

    if item["type"] != "function":
        raise ValueError(item)
    return item["name"] + str_tuple(item["inputs"])


def find_abi(abi: List, fun_info: FunctionInfo) -> Dict:
    funname, funsig = fun_info.name, fun_info.sig
    for item in abi:
        if (
            item["type"] == "function"
            and item["name"] == funname
            and str_abi(item) == funsig
        ):
            return item
    raise ValueError(f"No {funsig} found in {abi}")


def mk_calldata(
    abi: List,
    fun_info: FunctionInfo,
    cd: ByteVec,
    dyn_param_size: List[str],
    args: HalmosConfig,
) -> None:
    # find function abi
    fun_abi = find_abi(abi, fun_info)

    # no parameters
    if len(fun_abi["inputs"]) == 0:
        return

    # generate symbolic ABI calldata
    calldata = Calldata(args, mk_arrlen(args), dyn_param_size)
    calldata.create(fun_abi, cd)


def mk_callvalue() -> Word:
    return BitVec("msg_value", 256)


def mk_balance() -> Word:
    return Array("balance_0", BitVecSort(160), BitVecSort(256))


def mk_block() -> Block:
    block = Block(
        basefee=ZeroExt(160, BitVec("block_basefee", 96)),  # practical limit 96 bit
        chainid=ZeroExt(192, BitVec("block_chainid", 64)),  # chainid 64 bit
        coinbase=mk_addr("block_coinbase"),  # address 160 bit
        difficulty=BitVec("block_difficulty", 256),
        gaslimit=ZeroExt(160, BitVec("block_gaslimit", 96)),  # practical limit 96 bit
        number=ZeroExt(192, BitVec("block_number", 64)),  # practical limit 64 bit
        timestamp=ZeroExt(192, BitVec("block_timestamp", 64)),  # practical limit 64 bit
    )
    block.chainid = con(1)  # for ethereum
    return block


def mk_addr(name: str) -> Address:
    return BitVec(name, 160)


def mk_caller(args: HalmosConfig) -> Address:
    return mk_addr("msg_sender") if args.symbolic_msg_sender else magic_address


def mk_this() -> Address:
    return magic_address + 1


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
        except:
            pass

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


def run_bytecode(hexcode: str, args: HalmosConfig) -> List[Exec]:
    solver = mk_solver(args)
    this = mk_this()
    message = Message(
        target=this,
        caller=mk_caller(args),
        origin=mk_addr("tx_origin"),
        value=mk_callvalue(),
        data=ByteVec(),
        call_scheme=EVM.CALL,
    )

    contract = Contract.from_hexcode(hexcode)
    sevm = SEVM(args)
    ex = sevm.mk_exec(
        code={this: contract},
        storage={this: {}},
        balance=mk_balance(),
        block=mk_block(),
        context=CallContext(message=message),
        pgm=contract,
        symbolic=args.symbolic_storage,
        path=Path(solver),
    )
    exs = sevm.run(ex)
    result_exs = []

    for idx, ex in enumerate(exs):
        result_exs.append(ex)
        opcode = ex.current_opcode()
        error = ex.context.output.error
        returndata = ex.context.output.data

        if error:
            warn_code(
                INTERNAL_ERROR,
                f"{mnemonic(opcode)} failed, error={error}, returndata={returndata}",
            )
        else:
            print(f"Final opcode: {mnemonic(opcode)})")
            print(f"Return data: {returndata}")
            dump_dirname = f"/tmp/halmos-{uuid.uuid4().hex}"
            model_with_context = gen_model_from_sexpr(
                GenModelArgs(args, idx, ex.path.to_smt2(args), {}, dump_dirname)
            )
            print(f"Input example: {model_with_context.model}")

        if args.print_states:
            print(f"# {idx+1}")
            print(ex)

    return result_exs


def deploy_test(
    creation_hexcode: str,
    deployed_hexcode: str,
    sevm: SEVM,
    args: HalmosConfig,
    libs: Dict,
) -> Exec:
    this = mk_this()
    message = Message(
        target=this,
        caller=mk_caller(args),
        origin=mk_addr("tx_origin"),
        value=0,
        data=ByteVec(),
        call_scheme=EVM.CREATE,
    )

    ex = sevm.mk_exec(
        code={this: Contract(b"")},
        storage={this: {}},
        balance=mk_balance(),
        block=mk_block(),
        context=CallContext(message=message),
        pgm=None,  # to be added
        symbolic=False,
        path=Path(mk_solver(args)),
    )

    # deploy libraries and resolve library placeholders in hexcode
    (creation_hexcode, deployed_hexcode) = ex.resolve_libs(
        creation_hexcode, deployed_hexcode, libs
    )

    # test contract creation bytecode
    creation_bytecode = Contract.from_hexcode(creation_hexcode)
    ex.pgm = creation_bytecode

    # use the given deployed bytecode if --no-test-constructor is enabled
    if args.no_test_constructor:
        deployed_bytecode = Contract.from_hexcode(deployed_hexcode)
        ex.code[this] = deployed_bytecode
        ex.pgm = deployed_bytecode
        return ex

    # create test contract
    exs = list(sevm.run(ex))

    # sanity check
    if len(exs) != 1:
        raise ValueError(f"constructor: # of paths: {len(exs)}")

    ex = exs[0]

    if args.verbose >= VERBOSITY_TRACE_CONSTRUCTOR:
        print("Constructor trace:")
        render_trace(ex.context)

    error = ex.context.output.error
    returndata = ex.context.output.data
    if error:
        raise ValueError(f"constructor failed, error={error} returndata={returndata}")

    deployed_bytecode = Contract(returndata)
    ex.code[this] = deployed_bytecode
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
    abi: List,
    setup_info: FunctionInfo,
    args: HalmosConfig,
    libs: Dict,
) -> Exec:
    setup_timer = NamedTimer("setup")
    setup_timer.create_subtimer("decode")

    sevm = SEVM(args)
    setup_ex = deploy_test(creation_hexcode, deployed_hexcode, sevm, args, libs)

    setup_timer.create_subtimer("run")

    setup_sig, setup_selector = (setup_info.sig, setup_info.selector)
    if setup_sig:
        calldata = ByteVec()
        calldata.append(int(setup_selector, 16).to_bytes(4, "big"))

        dyn_param_size = []  # TODO: propagate to run
        mk_calldata(abi, setup_info, calldata, dyn_param_size, args)

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

            opcode = setup_ex.current_opcode()
            error = setup_ex.context.output.error

            if error is None:
                setup_exs_no_error.append((setup_ex, setup_ex.path.to_smt2(args)))

            else:
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
            info(
                f"Warning: multiple paths were found in {setup_sig}; "
                "an arbitrary path has been selected for the following tests."
            )

            if args.debug:
                print("\n".join(map(str, setup_exs)))

        setup_ex = setup_exs[0]

        if args.print_setup_states:
            print(setup_ex)

        if sevm.logs.bounded_loops:
            warn_code(
                LOOP_BOUND,
                f"{setup_sig}: paths have not been fully explored due to the loop unrolling bound: {args.loop}",
            )
            if args.debug:
                print("\n".join(sevm.logs.bounded_loops))

    if args.reset_bytecode:
        for assign in [x.split("=") for x in args.reset_bytecode.split(",")]:
            addr = con_addr(int(assign[0].strip(), 0))
            new_hexcode = assign[1].strip()
            setup_ex.code[addr] = Contract.from_hexcode(new_hexcode)

    if args.statistics:
        print(setup_timer.report())

    return setup_ex


@dataclass(frozen=True)
class ModelWithContext:
    # can be a filename containing the model or a dict with variable assignments
    model: Optional[UnionType[StrModel, str]]
    is_valid: Optional[bool]
    index: int
    result: CheckSatResult
    unsat_core: Optional[List]


@dataclass(frozen=True)
class TestResult:
    name: str  # test function name
    exitcode: int
    num_models: int = None
    models: List[ModelWithContext] = None
    num_paths: Tuple[int, int, int] = None  # number of paths: [total, success, blocked]
    time: Tuple[int, int, int] = None  # time: [total, paths, models]
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
    abi: List,
    fun_info: FunctionInfo,
    args: HalmosConfig,
) -> TestResult:
    funname, funsig, funselector = fun_info.name, fun_info.sig, fun_info.selector
    if args.verbose >= 1:
        print(f"Executing {funname}")

    dump_dirname = f"/tmp/{funname}-{uuid.uuid4().hex}"

    #
    # calldata
    #

    cd = ByteVec()
    cd.append(int(funselector, 16).to_bytes(4, "big"))

    dyn_param_size = []
    mk_calldata(abi, fun_info, cd, dyn_param_size, args)

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

    sevm = SEVM(args)
    solver = mk_solver(args)
    path = Path(solver)
    path.extend_path(setup_ex.path)

    exs = sevm.run(
        Exec(
            code=setup_ex.code.copy(),  # shallow copy
            storage=deepcopy(setup_ex.storage),
            balance=setup_ex.balance,  # TODO: add callvalue
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
            symbolic=args.symbolic_storage,
            #
            path=path,
            alias=setup_ex.alias.copy(),
            #
            cnts=deepcopy(setup_ex.cnts),
            sha3s=setup_ex.sha3s.copy(),
            storages=setup_ex.storages.copy(),
            balances=setup_ex.balances.copy(),
            calls=setup_ex.calls.copy(),
        )
    )

    (logs, steps) = (sevm.logs, sevm.steps)

    # check assertion violations
    normal = 0
    execs_to_model = []
    models: List[ModelWithContext] = []
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

        model, is_valid, index, result = m.model, m.is_valid, m.index, m.result
        if result == unsat:
            if m.unsat_core:
                unsat_cores.append(m.unsat_core)
            return

        # model could be an empty dict here
        if model is not None:
            if is_valid:
                print(red(f"Counterexample: {render_model(model)}"))
                counterexamples.append(model)
            else:
                warn_code(
                    COUNTEREXAMPLE_INVALID,
                    f"Counterexample (potentially invalid): {render_model(model)}",
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

        error = ex.context.output.error

        if (
            isinstance(error, Revert)
            and unbox_int(ex.context.output.data) == ASSERT_FAIL
        ) or is_global_fail_set(ex.context):
            if args.verbose >= 1:
                print(f"Found potential path (id: {idx+1})")
                print(f"{ex.context.output.error}")

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

        elif not error:
            normal += 1

        # 0 width is unlimited
        if args.width and len(result_exs) >= args.width:
            break

    timer.create_subtimer("models")

    if len(future_models) > 0 and args.verbose >= 1:
        print(
            f"# of potential paths involving assertion violations: {len(future_models)} / {len(result_exs)}  (--solver-threads {args.solver_threads})"
        )

    if args.early_exit:
        while not (
            len(counterexamples) > 0 or all([fm.done() for fm in future_models])
        ):
            time.sleep(1)

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
        f"{passfail} {funsig} (paths: {len(result_exs)}, {time_info}, bounds: [{', '.join(dyn_param_size)}])"
    )

    for idx, ex, err in stuck:
        warn_code(INTERNAL_ERROR, f"Encountered {err}")
        if args.print_blocked_states:
            print(f"\nPath #{idx+1}")
            print(traces[idx], end="")

    if logs.bounded_loops:
        warn_code(
            LOOP_BOUND,
            f"{funsig}: paths have not been fully explored due to the loop unrolling bound: {args.loop}",
        )
        if args.debug:
            print("\n".join(logs.bounded_loops))

    if logs.unknown_calls:
        warn_code(
            UNINTERPRETED_UNKNOWN_CALLS,
            f"{funsig}: unknown calls have been assumed to be static: {', '.join(logs.unknown_calls)}",
        )
        if args.debug:
            logs.print_unknown_calls()

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


@dataclass(frozen=True)
class SetupAndRunSingleArgs:
    creation_hexcode: str
    deployed_hexcode: str
    abi: List
    setup_info: FunctionInfo
    fun_info: FunctionInfo
    setup_args: HalmosConfig
    args: HalmosConfig
    libs: Dict


def setup_and_run_single(fn_args: SetupAndRunSingleArgs) -> List[TestResult]:
    args = fn_args.args
    try:
        setup_ex = setup(
            fn_args.creation_hexcode,
            fn_args.deployed_hexcode,
            fn_args.abi,
            fn_args.setup_info,
            fn_args.setup_args,
            fn_args.libs,
        )
    except Exception as err:
        error(f"Error: {fn_args.setup_info.sig} failed: {type(err).__name__}: {err}")

        if args.debug:
            traceback.print_exc()
        return []

    try:
        test_result = run(
            setup_ex,
            fn_args.abi,
            fn_args.fun_info,
            fn_args.args,
        )
    except Exception as err:
        print(f"{color_error('[ERROR]')} {fn_args.fun_info.sig}")
        error(f"{type(err).__name__}: {err}")
        if args.debug:
            traceback.print_exc()
        return [TestResult(fn_args.fun_info.sig, Exitcode.EXCEPTION.value)]

    return [test_result]


def extract_setup(methodIdentifiers: Dict[str, str]) -> FunctionInfo:
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
    funsigs: List[str]

    # code of the current contract
    creation_hexcode: str
    deployed_hexcode: str

    abi: List
    methodIdentifiers: Dict[str, str]

    args: HalmosConfig
    contract_json: Dict
    libs: Dict


def run_parallel(run_args: RunArgs) -> List[TestResult]:
    args = run_args.args
    creation_hexcode, deployed_hexcode, abi, methodIdentifiers, libs = (
        run_args.creation_hexcode,
        run_args.deployed_hexcode,
        run_args.abi,
        run_args.methodIdentifiers,
        run_args.libs,
    )

    setup_info = extract_setup(methodIdentifiers)
    setup_config = with_devdoc(args, setup_info.sig, run_args.contract_json)
    fun_infos = [
        FunctionInfo(funsig.split("(")[0], funsig, methodIdentifiers[funsig])
        for funsig in run_args.funsigs
    ]

    single_run_args = [
        SetupAndRunSingleArgs(
            creation_hexcode,
            deployed_hexcode,
            abi,
            setup_info,
            fun_info,
            setup_config,
            with_devdoc(args, fun_info.sig, run_args.contract_json),
            libs,
        )
        for fun_info in fun_infos
    ]

    # dispatch to the shared process pool
    with ProcessPoolExecutor() as process_pool:
        test_results = list(process_pool.map(setup_and_run_single, single_run_args))
    test_results = sum(test_results, [])  # flatten lists

    return test_results


def run_sequential(run_args: RunArgs) -> List[TestResult]:
    args = run_args.args
    setup_info = extract_setup(run_args.methodIdentifiers)

    try:
        setup_config = with_devdoc(args, setup_info.sig, run_args.contract_json)
        setup_ex = setup(
            run_args.creation_hexcode,
            run_args.deployed_hexcode,
            run_args.abi,
            setup_info,
            setup_config,
            run_args.libs,
        )
    except Exception as err:
        error(f"Error: {setup_info.sig} failed: {type(err).__name__}: {err}")
        if args.debug:
            traceback.print_exc()
        return []

    test_results = []
    for funsig in run_args.funsigs:
        fun_info = FunctionInfo(
            funsig.split("(")[0], funsig, run_args.methodIdentifiers[funsig]
        )
        try:
            test_config = with_devdoc(args, funsig, run_args.contract_json)
            if test_config.debug:
                debug(f"{test_config.formatted_layers()}")
            test_result = run(setup_ex, run_args.abi, fun_info, test_config)
        except Exception as err:
            print(f"{color_error('[ERROR]')} {funsig}")
            error(f"{type(err).__name__}: {err}")
            if args.debug:
                traceback.print_exc()
            test_results.append(TestResult(funsig, Exitcode.EXCEPTION.value))
            continue

        test_results.append(test_result)

    return test_results


@dataclass(frozen=True)
class GenModelArgs:
    args: HalmosConfig
    idx: int
    sexpr: SMTQuery
    known_unsat_cores: List[List]
    dump_dirname: Optional[str] = None


def copy_model(model: Model) -> Dict:
    return {decl: model[decl] for decl in model}


def parse_unsat_core(output) -> Optional[List]:
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
    query: SMTQuery, args: HalmosConfig, dump_filename: Optional[str] = None
) -> Tuple[CheckSatResult, Model, Optional[List]]:
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
                print(f"Writing SMT query to {dump_filename}")
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
            print(f"  Checking with external solver process")
            print(f"    {args.solver_command} {dump_filename} >{dump_filename}.out")

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
                print(f"    {res_str_head}")

            if res_str_head == "unsat":
                unsat_core = parse_unsat_core(res_str) if args.cache_solver else None
                return unsat, None, unsat_core
            elif res_str_head == "sat":
                return sat, f"{dump_filename}.out", None
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
        model = copy_model(solver.model()) if result == sat else None
        unsat_core = (
            [str(core) for core in solver.unsat_core()]
            if args.cache_solver and result == unsat
            else None
        )
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
    if args.dump_smt_queries or args.solver_command:
        if not os.path.isdir(dump_dirname):
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

    if res == sat and not is_model_valid(model):
        if args.verbose >= 1:
            print(f"  Checking again with refinement")

        refined_filename = dump_filename.replace(".smt2", ".refined.smt2")
        res, model, unsat_core = solve(refine(sexpr), args, refined_filename)

    return package_result(model, idx, res, unsat_core, args)


def is_unknown(result: CheckSatResult, model: Model) -> bool:
    return result == unknown or (result == sat and not is_model_valid(model))


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
    model: Optional[UnionType[Model, str]],
    idx: int,
    result: CheckSatResult,
    unsat_core: Optional[List],
    args: HalmosConfig,
) -> ModelWithContext:
    if result == unsat:
        if args.verbose >= 1:
            print(f"  Invalid path; ignored (path id: {idx+1})")
        return ModelWithContext(None, None, idx, result, unsat_core)

    if result == sat:
        if args.verbose >= 1:
            print(f"  Valid path; counterexample generated (path id: {idx+1})")

        # convert model into string to avoid pickling errors for z3 (ctypes) objects containing pointers
        is_valid = None
        if model:
            if isinstance(model, str):
                is_valid = True
                model = f"see {model}"
            else:
                is_valid = is_model_valid(model)
                model = to_str_model(model, args.print_full_model)

        return ModelWithContext(model, is_valid, idx, result, None)

    else:
        if args.verbose >= 1:
            print(f"  Timeout (path id: {idx+1})")
        return ModelWithContext(None, None, idx, result, None)


def is_model_valid(model: AnyModel) -> bool:
    # TODO: evaluate the path condition against the given model after excluding f_evm_* symbols,
    #       since the f_evm_* symbols may still appear in valid models.

    # model is a filename, containing solver output
    if isinstance(model, str):
        with open(model, "r") as f:
            for line in f:
                if "f_evm_" in line:
                    return False
        return True

    # z3 model object
    else:
        for decl in model:
            if str(decl).startswith("f_evm_"):
                return False
        return True


def to_str_model(model: Model, print_full_model: bool) -> StrModel:
    def select(var):
        name = str(var)
        return name.startswith("p_") or name.startswith("halmos_")

    select_model = filter(select, model) if not print_full_model else model
    return {str(decl): stringify(str(decl), model[decl]) for decl in select_model}


def render_model(model: UnionType[str, StrModel]) -> str:
    if isinstance(model, str):
        return model

    formatted = [f"\n    {decl} = {val}" for decl, val in model.items()]
    return "".join(sorted(formatted)) if formatted else "∅"


def mk_arrlen(args: HalmosConfig) -> Dict[str, int]:
    arrlen = {}
    if args.array_lengths:
        for assign in [x.split("=") for x in args.array_lengths.split(",")]:
            name = assign[0].strip()
            size = assign[1].strip()
            arrlen[name] = int(size)
    return arrlen


def get_contract_type(
    ast_nodes: Dict, contract_name: str
) -> Tuple[str | None, str | None]:
    for node in ast_nodes:
        if node["nodeType"] == "ContractDefinition" and node["name"] == contract_name:
            abstract = "abstract " if node.get("abstract") else ""
            contract_type = abstract + node["contractKind"]
            natspec = node.get("documentation")
            return contract_type, natspec

    return None, None


def parse_build_out(args: HalmosConfig) -> Dict:
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
                    if args.debug:
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


def parse_symbols(args: HalmosConfig, contract_map: Dict, contract_name: str) -> None:
    try:
        json_out = contract_map[contract_name][0]
        bytecode = json_out["bytecode"]["object"]
        contract_mapping_info = Mapper().get_or_create(contract_name)
        contract_mapping_info.bytecode = bytecode

        Mapper().parse_ast(json_out["ast"])

    except Exception:
        if args.debug:
            debug(f"error parsing symbols for contract {contract_name}")
            debug(traceback.format_exc())
        else:
            # we parse symbols as best effort, don't propagate exceptions
            pass


def parse_devdoc(funsig: str, contract_json: Dict) -> str:
    try:
        return contract_json["metadata"]["output"]["devdoc"]["methods"][funsig][
            "custom:halmos"
        ]
    except KeyError as err:
        return None


def parse_natspec(natspec: Dict) -> str:
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


def import_libs(build_out_map: Dict, hexcode: str, linkReferences: Dict) -> Dict:
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


def build_output_iterator(build_out: Dict):
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
    test_results: Dict[str, List[TestResult]] = None


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

    # quick bytecode execution mode
    if args.bytecode is not None:
        run_bytecode(args.bytecode, args)
        return MainResult(0)

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
    if args.debug:
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
            if args.debug:
                debug(f"Writing output to {args.json_output}")
            with open(args.json_output, "w") as json_file:
                json.dump(asdict(result), json_file, indent=4)

        return result

    def on_signal(signum, frame):
        if args.debug:
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

        abi = contract_json["abi"]
        creation_hexcode = contract_json["bytecode"]["object"]
        deployed_hexcode = contract_json["deployedBytecode"]["object"]
        linkReferences = contract_json["bytecode"]["linkReferences"]
        libs = import_libs(build_out_map, creation_hexcode, linkReferences)

        contract_path = f"{contract_json['ast']['absolutePath']}:{contract_name}"
        print(f"\nRunning {num_found} tests for {contract_path}")

        # Set 0xaaaa0001 in DeployAddressMapper
        DeployAddressMapper().add_deployed_contract("0xaaaa0001", contract_name)

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
        )

        enable_parallel = args.test_parallel and num_found > 1
        run_method = run_parallel if enable_parallel else run_sequential
        test_results = run_method(run_args)

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
            f"Error: No tests with"
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
