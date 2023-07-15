# SPDX-License-Identifier: AGPL-3.0

import os
import sys
import subprocess
import uuid
import json
import argparse
import re
import traceback

from dataclasses import dataclass
from timeit import default_timer as timer
from importlib import metadata

from .pools import thread_pool, process_pool
from .sevm import *
from .utils import color_good, color_warn, hexify
from .warnings import *

SETUP_FAILED = 127
TEST_FAILED = 128

args: argparse.Namespace


# Python version >=3.8.14, >=3.9.14, >=3.10.7, or >=3.11
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(0)


def parse_args(args=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="halmos", epilog="For more information, see https://github.com/a16z/halmos"
    )

    parser.add_argument(
        "--root",
        metavar="DIRECTORY",
        default=os.getcwd(),
        help="source root directory (default: current directory)",
    )
    parser.add_argument(
        "--contract",
        metavar="CONTRACT_NAME",
        help="run tests in the given contract only",
    )
    parser.add_argument(
        "--function",
        metavar="FUNCTION_NAME_PREFIX",
        default="check",
        help="run tests matching the given prefix only (default: %(default)s)",
    )

    parser.add_argument(
        "--loop",
        metavar="MAX_BOUND",
        type=int,
        default=2,
        help="set loop unrolling bounds (default: %(default)s)",
    )
    parser.add_argument(
        "--width", metavar="MAX_WIDTH", type=int, help="set the max number of paths"
    )
    parser.add_argument(
        "--depth", metavar="MAX_DEPTH", type=int, help="set the max path length"
    )
    parser.add_argument(
        "--array-lengths",
        metavar="NAME1=LENGTH1,NAME2=LENGTH2,...",
        help="set the length of dynamic-sized arrays including bytes and string (default: loop unrolling bound)",
    )

    parser.add_argument(
        "--symbolic-storage",
        action="store_true",
        help="set default storage values to symbolic",
    )
    parser.add_argument(
        "--symbolic-msg-sender", action="store_true", help="set msg.sender symbolic"
    )

    parser.add_argument(
        "--version", action="store_true", help="print the version number"
    )

    # debugging options
    group_debug = parser.add_argument_group("Debugging options")

    group_debug.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="increase verbosity levels: -v, -vv, -vvv, ...",
    )
    group_debug.add_argument(
        "-st", "--statistics", action="store_true", help="print statistics"
    )
    group_debug.add_argument("--debug", action="store_true", help="run in debug mode")
    group_debug.add_argument(
        "--log", metavar="LOG_FILE_PATH", help="log every execution steps in JSON"
    )
    group_debug.add_argument(
        "--print-steps", action="store_true", help="print every execution steps"
    )
    group_debug.add_argument(
        "--print-states", action="store_true", help="print all final execution states"
    )
    group_debug.add_argument(
        "--print-failed-states",
        action="store_true",
        help="print failed execution states",
    )
    group_debug.add_argument(
        "--print-blocked-states",
        action="store_true",
        help="print blocked execution states",
    )
    group_debug.add_argument(
        "--print-setup-states", action="store_true", help="print setup execution states"
    )
    group_debug.add_argument(
        "--print-full-model",
        action="store_true",
        help="print full counterexample model",
    )

    # build options
    group_build = parser.add_argument_group("Build options")

    group_build.add_argument(
        "--forge-build-out",
        metavar="DIRECTORY_NAME",
        default="out",
        help="forge build artifacts directory name (default: %(default)s)",
    )

    # smt solver options
    group_solver = parser.add_argument_group("Solver options")

    group_solver.add_argument(
        "--no-smt-add", action="store_true", help="do not interpret `+`"
    )
    group_solver.add_argument(
        "--no-smt-sub", action="store_true", help="do not interpret `-`"
    )
    group_solver.add_argument(
        "--no-smt-mul", action="store_true", help="do not interpret `*`"
    )
    group_solver.add_argument("--smt-div", action="store_true", help="interpret `/`")
    group_solver.add_argument("--smt-mod", action="store_true", help="interpret `mod`")
    group_solver.add_argument(
        "--smt-div-by-const", action="store_true", help="interpret division by constant"
    )
    group_solver.add_argument(
        "--smt-mod-by-const", action="store_true", help="interpret constant modulo"
    )
    group_solver.add_argument(
        "--smt-exp-by-const",
        metavar="N",
        type=int,
        default=2,
        help="interpret constant power up to N (default: %(default)s)",
    )

    group_solver.add_argument(
        "--solver-timeout-branching",
        metavar="TIMEOUT",
        type=int,
        default=1,
        help="set timeout (in milliseconds) for solving branching conditions (default: %(default)s)",
    )
    group_solver.add_argument(
        "--solver-timeout-assertion",
        metavar="TIMEOUT",
        type=int,
        default=1000,
        help="set timeout (in milliseconds) for solving assertion violation conditions (default: %(default)s)",
    )
    group_solver.add_argument(
        "--solver-fresh",
        action="store_true",
        help="run an extra solver with a fresh state for unknown",
    )
    group_solver.add_argument(
        "--solver-subprocess",
        action="store_true",
        help="run an extra solver in subprocess for unknown",
    )
    group_solver.add_argument(
        "--solver-parallel",
        action="store_true",
        help="run assertion solvers in parallel",
    )

    # internal options
    group_internal = parser.add_argument_group("Internal options")

    group_internal.add_argument(
        "--bytecode", metavar="HEX_STRING", help="execute the given bytecode"
    )
    group_internal.add_argument(
        "--reset-bytecode",
        metavar="ADDR1=CODE1,ADDR2=CODE2,...",
        help="reset the bytecode of given addresses after setUp()",
    )
    group_internal.add_argument(
        "--test-parallel", action="store_true", help="run tests in parallel"
    )

    # experimental options
    group_experimental = parser.add_argument_group("Experimental options")

    group_experimental.add_argument(
        "--symbolic-jump", action="store_true", help="support symbolic jump destination"
    )
    group_experimental.add_argument(
        "--print-potential-counterexample",
        action="store_true",
        help="print potentially invalid counterexamples",
    )

    return parser.parse_args(args)


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
            if typ == "tuple":
                ret.append(str_tuple(arg["components"]))
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
    cd: List,
    dyn_param_size: List[str],
    args: argparse.Namespace,
) -> None:
    item = find_abi(abi, fun_info)
    tba = []
    offset = 0
    for param in item["inputs"]:
        param_name = param["name"]
        param_type = param["type"]
        if param_type == "tuple":
            # TODO: support struct types
            raise NotImplementedError(f"Not supported parameter type: {param_type}")
        elif param_type == "bytes" or param_type == "string":
            # wstore(cd, 4+offset, 32, BitVecVal(<?offset?>, 256))
            tba.append((4 + offset, param))
            offset += 32
        elif param_type.endswith("[]"):
            raise NotImplementedError(f"Not supported dynamic arrays: {param_type}")
        else:
            match = re.search(
                r"(u?int[0-9]*|address|bool|bytes[0-9]+)(\[([0-9]+)\])?", param_type
            )
            if not match:
                raise NotImplementedError(f"Unknown parameter type: {param_type}")
            typ = match.group(1)
            dim = match.group(3)
            if dim:  # array
                for idx in range(int(dim)):
                    wstore(
                        cd, 4 + offset, 32, BitVec(f"p_{param_name}[{idx}]_{typ}", 256)
                    )
                    offset += 32
            else:  # primitive
                wstore(cd, 4 + offset, 32, BitVec(f"p_{param_name}_{typ}", 256))
                offset += 32

    arrlen = mk_arrlen(args)
    for loc_param in tba:
        loc = loc_param[0]
        param = loc_param[1]
        param_name = param["name"]
        param_type = param["type"]

        if param_name not in arrlen:
            size = args.loop
            if args.debug:
                print(
                    f"Warning: no size provided for {param_name}; default value {size} will be used."
                )
        else:
            size = arrlen[param_name]

        dyn_param_size.append(f"|{param_name}|={size}")

        if param_type == "bytes" or param_type == "string":
            # head
            wstore(cd, loc, 32, BitVecVal(offset, 256))
            # tail
            size_pad_right = int((size + 31) / 32) * 32
            wstore(cd, 4 + offset, 32, BitVecVal(size, 256))
            offset += 32
            if size_pad_right > 0:
                wstore(
                    cd,
                    4 + offset,
                    size_pad_right,
                    BitVec(f"p_{param_name}_{param_type}", 8 * size_pad_right),
                )
                offset += size_pad_right
        else:
            raise ValueError(param_type)


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


def mk_caller(args: argparse.Namespace) -> Address:
    if args.symbolic_msg_sender:
        return mk_addr("msg_sender")
    else:
        return con_addr(magic_address)


def mk_this() -> Address:
    return con_addr(magic_address + 1)


def mk_solver(args: argparse.Namespace):
    # quantifier-free bitvector + array theory; https://smtlib.cs.uiowa.edu/logics.shtml
    solver = SolverFor("QF_AUFBV")
    solver.set(timeout=args.solver_timeout_branching)
    return solver


def run_bytecode(hexcode: str) -> List[Exec]:
    contract = Contract.from_hexcode(hexcode)

    storage = {}

    solver = mk_solver(args)

    balance = mk_balance()
    block = mk_block()
    callvalue = mk_callvalue()
    caller = mk_caller(args)
    this = mk_this()
    options = mk_options(args)

    sevm = SEVM(options)
    ex = sevm.mk_exec(
        code={this: contract},
        storage={this: storage},
        balance=balance,
        block=block,
        calldata=[],
        callvalue=callvalue,
        caller=caller,
        this=this,
        symbolic=args.symbolic_storage,
        solver=solver,
    )
    (exs, _, _) = sevm.run(ex)

    for idx, ex in enumerate(exs):
        opcode = ex.current_opcode()
        if opcode in [EVM.STOP, EVM.RETURN, EVM.REVERT, EVM.INVALID]:
            model_with_context = gen_model(args, idx, ex)
            print(
                f"Final opcode: {mnemonic(opcode)} | Return data: {ex.output} | Input example: {model_with_context.model}"
            )
        else:
            print(color_warn(f"Not supported: {mnemonic(opcode)} {ex.error}"))
        if args.print_states:
            print(f"# {idx+1} / {len(exs)}")
            print(ex)

    return exs


def setup(
    hexcode: str,
    abi: List,
    setup_info: FunctionInfo,
    args: argparse.Namespace,
) -> Exec:
    setup_start = timer()

    contract = Contract.from_hexcode(hexcode)

    solver = mk_solver(args)
    this = mk_this()
    options = mk_options(args)

    sevm = SEVM(options)

    setup_ex = sevm.mk_exec(
        code={this: contract},
        storage={this: {}},
        balance=mk_balance(),
        block=mk_block(),
        calldata=[],
        callvalue=con(0),
        caller=mk_caller(args),
        this=this,
        symbolic=False,
        solver=solver,
    )

    setup_mid = timer()

    setup_sig, setup_name, setup_selector = (
        setup_info.sig,
        setup_info.name,
        setup_info.selector,
    )
    if setup_sig:
        wstore(setup_ex.calldata, 0, 4, BitVecVal(int(setup_selector, 16), 32))
        dyn_param_size = []  # TODO: propagate to run
        mk_calldata(abi, setup_info, setup_ex.calldata, dyn_param_size, args)

        (setup_exs_all, setup_steps, setup_bounded_loops) = sevm.run(setup_ex)

        if setup_bounded_loops:
            warn(
                LOOP_BOUND,
                f"{setup_sig}: paths have not been fully explored due to the loop unrolling bound: {args.loop}",
            )
            if args.debug:
                print("\n".join(setup_bounded_loops))

        setup_exs = []

        for idx, setup_ex in enumerate(setup_exs_all):
            opcode = setup_ex.current_opcode()
            if opcode in [EVM.STOP, EVM.RETURN]:
                setup_ex.solver.set(timeout=args.solver_timeout_assertion)
                res = setup_ex.solver.check()
                if res != unsat:
                    setup_exs.append(setup_ex)
            elif opcode not in [EVM.REVERT, EVM.INVALID]:
                print(
                    color_warn(
                        f"Warning: {setup_sig} execution encountered an issue at {mnemonic(opcode)}: {setup_ex.error}"
                    )
                )

        if len(setup_exs) == 0:
            raise ValueError(f"No successful path found in {setup_sig}")
        if len(setup_exs) > 1:
            print(
                color_warn(
                    f"Warning: multiple paths were found in {setup_sig}; an arbitrary path has been selected for the following tests."
                )
            )
            if args.debug:
                print("\n".join(map(str, setup_exs)))

        setup_ex = setup_exs[0]

        if args.print_setup_states:
            print(setup_ex)

    if args.reset_bytecode:
        for assign in [x.split("=") for x in args.reset_bytecode.split(",")]:
            addr = con_addr(int(assign[0].strip(), 0))
            new_hexcode = assign[1].strip()
            setup_ex.code[addr] = Contract.from_hexcode(new_hexcode)

    setup_end = timer()

    if args.statistics:
        print(
            f"[time] setup: {setup_end - setup_start:0.2f}s (decode: {setup_mid - setup_start:0.2f}s, run: {setup_end - setup_mid:0.2f}s)"
        )

    return setup_ex


@dataclass(frozen=True)
class ModelWithContext:
    model: str
    validity: bool
    index: int
    result: CheckSatResult


def run(
    setup_ex: Exec,
    abi: List,
    fun_info: FunctionInfo,
    args: argparse.Namespace,
) -> int:
    funname, funsig, funselector = fun_info.name, fun_info.sig, fun_info.selector
    if args.verbose >= 1:
        print(f"Executing {funname}")

    #
    # calldata
    #

    cd = []

    wstore(cd, 0, 4, BitVecVal(int(funselector, 16), 32))

    dyn_param_size = []
    mk_calldata(abi, fun_info, cd, dyn_param_size, args)

    #
    # callvalue
    #

    callvalue = mk_callvalue()

    #
    # run
    #

    start = timer()

    options = mk_options(args)
    sevm = SEVM(options)

    solver = SolverFor("QF_AUFBV")
    solver.set(timeout=args.solver_timeout_branching)
    solver.add(setup_ex.solver.assertions())

    (exs, steps, bounded_loops) = sevm.run(
        Exec(
            code=setup_ex.code.copy(),  # shallow copy
            storage=deepcopy(setup_ex.storage),
            balance=setup_ex.balance,  # TODO: add callvalue
            #
            block=deepcopy(setup_ex.block),
            #
            calldata=cd,
            callvalue=callvalue,
            caller=setup_ex.caller,
            this=setup_ex.this,
            #
            pc=0,
            st=State(),
            jumpis={},
            output=None,
            symbolic=args.symbolic_storage,
            prank=Prank(),  # prank is reset after setUp()
            #
            solver=solver,
            path=deepcopy(setup_ex.path),
            #
            log=deepcopy(setup_ex.log),
            cnts=deepcopy(setup_ex.cnts),
            sha3s=deepcopy(setup_ex.sha3s),
            storages=deepcopy(setup_ex.storages),
            balances=deepcopy(setup_ex.balances),
            calls=deepcopy(setup_ex.calls),
            failed=setup_ex.failed,
            error=setup_ex.error,
        )
    )

    mid = timer()

    # check assertion violations
    normal = 0
    execs_to_model = []
    models: List[ModelWithContext] = []
    stuck = []

    for idx, ex in enumerate(exs):
        opcode = ex.current_opcode()
        if opcode in [EVM.STOP, EVM.RETURN]:
            normal += 1
        elif opcode in [EVM.REVERT, EVM.INVALID]:
            # Panic(1)
            # bytes4(keccak256("Panic(uint256)")) + bytes32(1)
            if (
                unbox_int(ex.output)
                == 0x4E487B710000000000000000000000000000000000000000000000000000000000000001
            ):
                execs_to_model.append((idx, ex))
        elif ex.failed:
            execs_to_model.append((idx, ex))
        else:
            stuck.append((opcode, idx, ex))

    if len(execs_to_model) > 0 and args.verbose >= 1:
        print(
            f"# of potential paths involving assertion violations: {len(execs_to_model)} / {len(exs)}"
        )

    if len(execs_to_model) > 1 and args.solver_parallel:
        if args.verbose >= 1:
            print(f"Spawning {len(execs_to_model)} parallel assertion solvers")

        fn_args = [
            GenModelArgs(args, idx, ex.solver.to_smt2()) for idx, ex in execs_to_model
        ]
        models = [m for m in thread_pool.map(gen_model_from_sexpr, fn_args)]

    else:
        models = [gen_model(args, idx, ex) for idx, ex in execs_to_model]

    end = timer()

    no_counterexample = all(m.model is None for m in models)
    passed = no_counterexample and normal > 0 and len(stuck) == 0
    passfail = color_good("[PASS]") if passed else color_warn("[FAIL]")

    time_info = f"{end - start:0.2f}s"
    if args.statistics:
        time_info += f" (paths: {mid - start:0.2f}s, models: {end - mid:0.2f}s)"

    # print result
    print(
        f"{passfail} {funsig} (paths: {normal}/{len(exs)}, time: {time_info}, bounds: [{', '.join(dyn_param_size)}])"
    )
    for m in models:
        model, validity, idx, result = m.model, m.validity, m.index, m.result
        if result == unsat:
            continue
        ex = exs[idx]

        if model:
            if validity:
                print(color_warn(f"Counterexample: {model}"))
            elif args.print_potential_counterexample:
                warn(
                    COUNTEREXAMPLE_INVALID,
                    f"Counterexample (potentially invalid): {model}",
                )
            else:
                warn(
                    COUNTEREXAMPLE_INVALID,
                    f"Counterexample (potentially invalid): (not displayed, use --print-potential-counterexample)",
                )
        else:
            warn(COUNTEREXAMPLE_UNKNOWN, f"Counterexample: {result}")

        if args.print_failed_states:
            print(f"# {idx+1} / {len(exs)}")
            print(ex)

    for opcode, idx, ex in stuck:
        print(color_warn(f"Not supported: {mnemonic(opcode)}: {ex.error}"))
        if args.print_blocked_states:
            print(f"# {idx+1} / {len(exs)}")
            print(ex)

    if bounded_loops:
        warn(
            LOOP_BOUND,
            f"{funsig}: paths have not been fully explored due to the loop unrolling bound: {args.loop}",
        )
        if args.debug:
            print("\n".join(bounded_loops))

    # print post-states
    if args.print_states:
        for idx, ex in enumerate(exs):
            print(f"# {idx+1} / {len(exs)}")
            print(ex)

    # log steps
    if args.log:
        with open(args.log, "w") as json_file:
            json.dump(steps, json_file)

    # exitcode
    return 0 if passed else 1


@dataclass(frozen=True)
class SetupAndRunSingleArgs:
    hexcode: str
    abi: List
    setup_info: FunctionInfo
    fun_info: FunctionInfo
    args: argparse.Namespace


def setup_and_run_single(fn_args: SetupAndRunSingleArgs) -> int:
    try:
        setup_ex = setup(
            fn_args.hexcode,
            fn_args.abi,
            fn_args.setup_info,
            fn_args.args,
        )
    except Exception as err:
        print(
            color_warn(
                f"Error: {fn_args.setup_info.sig} failed: {type(err).__name__}: {err}"
            )
        )
        if args.debug:
            traceback.print_exc()
        return SETUP_FAILED

    try:
        exitcode = run(
            setup_ex,
            fn_args.abi,
            fn_args.fun_info,
            fn_args.args,
        )
    except Exception as err:
        print(f'{color_warn("[SKIP]")} {fn_args.fun_info.sig}')
        print(color_warn(f"{type(err).__name__}: {err}"))
        if args.debug:
            traceback.print_exc()
        return TEST_FAILED

    return exitcode


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
    hexcode: str

    abi: List
    methodIdentifiers: Dict[str, str]


def run_parallel(run_args: RunArgs) -> Tuple[int, int]:
    hexcode, abi, methodIdentifiers = (
        run_args.hexcode,
        run_args.abi,
        run_args.methodIdentifiers,
    )

    setup_info = extract_setup(methodIdentifiers)
    if setup_info.sig and args.verbose >= 1:
        print(f"Running {setup_info.sig}")

    fun_infos = [
        FunctionInfo(funsig.split("(")[0], funsig, methodIdentifiers[funsig])
        for funsig in run_args.funsigs
    ]
    single_run_args = [
        SetupAndRunSingleArgs(hexcode, abi, setup_info, fun_info, args)
        for fun_info in fun_infos
    ]

    # dispatch to the shared process pool
    exitcodes = list(process_pool.map(setup_and_run_single, single_run_args))

    num_passed = exitcodes.count(0)
    num_failed = len(exitcodes) - num_passed

    return num_passed, num_failed


def run_sequential(run_args: RunArgs) -> Tuple[int, int]:
    setup_info = extract_setup(run_args.methodIdentifiers)
    if setup_info.sig and args.verbose >= 1:
        print(f"Running {setup_info.sig}")

    try:
        setup_ex = setup(run_args.hexcode, run_args.abi, setup_info, args)
    except Exception as err:
        print(
            color_warn(f"Error: {setup_info.sig} failed: {type(err).__name__}: {err}")
        )
        if args.debug:
            traceback.print_exc()
        return (0, 0)

    num_passed, num_failed = 0, 0
    for funsig in run_args.funsigs:
        fun_info = FunctionInfo(
            funsig.split("(")[0], funsig, run_args.methodIdentifiers[funsig]
        )
        try:
            exitcode = run(setup_ex, run_args.abi, fun_info, args)
        except Exception as err:
            print(f'{color_warn("[SKIP]")} {funsig}')
            print(color_warn(f"{type(err).__name__}: {err}"))
            if args.debug:
                traceback.print_exc()
            num_failed += 1
            continue
        if exitcode == 0:
            num_passed += 1
        else:
            num_failed += 1

    return (num_passed, num_failed)


@dataclass(frozen=True)
class GenModelArgs:
    args: argparse.Namespace
    idx: int
    sexpr: str


def gen_model_from_sexpr(fn_args: GenModelArgs) -> ModelWithContext:
    args, idx, sexpr = fn_args.args, fn_args.idx, fn_args.sexpr
    solver = SolverFor("QF_AUFBV", ctx=Context())
    solver.set(timeout=args.solver_timeout_assertion)
    solver.from_string(sexpr)
    res = solver.check()
    model = solver.model() if res == sat else None

    # TODO: handle args.solver_subprocess

    return package_result(model, idx, res, args)


def is_unknown(result: CheckSatResult, model: Model) -> bool:
    return result == unknown or (result == sat and not is_valid_model(model))


def gen_model(args: argparse.Namespace, idx: int, ex: Exec) -> ModelWithContext:
    if args.verbose >= 1:
        print(f"Checking path condition (path id: {idx+1})")

    model = None

    ex.solver.set(timeout=args.solver_timeout_assertion)
    res = ex.solver.check()
    if res == sat:
        model = ex.solver.model()

    if is_unknown(res, model) and args.solver_fresh:
        if args.verbose >= 1:
            print(f"  Checking again with a fresh solver")
        sol2 = SolverFor("QF_AUFBV", ctx=Context())
        #   sol2.set(timeout=args.solver_timeout_assertion)
        sol2.from_string(ex.solver.to_smt2())
        res = sol2.check()
        if res == sat:
            model = sol2.model()

    if is_unknown(res, model) and args.solver_subprocess:
        if args.verbose >= 1:
            print(f"  Checking again in an external process")
        fname = f"/tmp/{uuid.uuid4().hex}.smt2"
        if args.verbose >= 1:
            print(f"    z3 -model {fname} >{fname}.out")
        query = ex.solver.to_smt2()
        # replace uninterpreted abstraction with actual symbols for assertion solving
        # TODO: replace `(evm_bvudiv x y)` with `(ite (= y (_ bv0 256)) (_ bv0 256) (bvudiv x y))`
        #       as bvudiv is undefined when y = 0; also similarly for evm_bvurem
        query = re.sub(r"(\(\s*)evm_(bv[a-z]+)(_[0-9]+)?\b", r"\1\2", query)
        with open(fname, "w") as f:
            f.write("(set-logic QF_AUFBV)\n")
            f.write(query)
        res_str = subprocess.run(
            ["z3", "-model", fname], capture_output=True, text=True
        ).stdout.strip()
        res_str_head = res_str.split("\n", 1)[0]
        with open(f"{fname}.out", "w") as f:
            f.write(res_str)
        if args.verbose >= 1:
            print(f"    {res_str_head}")
        if res_str_head == "unsat":
            res = unsat
        elif res_str_head == "sat":
            res = sat
            model = f"{fname}.out"

    return package_result(model, idx, res, args)


def package_result(
    model: UnionType[Model, str],
    idx: int,
    result: CheckSatResult,
    args: argparse.Namespace,
) -> ModelWithContext:
    if result == unsat:
        if args.verbose >= 1:
            print(f"  Invalid path; ignored (path id: {idx+1})")
        return ModelWithContext(None, None, idx, result)

    if result == sat:
        if args.verbose >= 1:
            print(f"  Valid path; counterexample generated (path id: {idx+1})")

        # convert model into string to avoid pickling errors for z3 (ctypes) objects containing pointers
        validity = None
        if model:
            if isinstance(model, str):
                validity = True
                model = f"see {model}"
            else:
                validity = is_valid_model(model)
                model = f"{str_model(model, args)}"

        return ModelWithContext(model, validity, idx, result)

    else:
        if args.verbose >= 1:
            print(f"  Timeout (path id: {idx+1})")
        return ModelWithContext(None, None, idx, result)


def is_valid_model(model) -> bool:
    for decl in model:
        if str(decl).startswith("evm_"):
            return False
    return True


def str_model(model, args: argparse.Namespace) -> str:
    def select(var):
        name = str(var)
        if name.startswith("p_"):
            return True
        if name.startswith("halmos_"):
            return True
        return False

    select_model = filter(select, model) if not args.print_full_model else model
    return (
        "["
        + ",".join(
            sorted(
                map(lambda decl: f"\n    {decl} = {hexify(model[decl])}", select_model)
            )
        )
        + "]"
    )


def mk_options(args: argparse.Namespace) -> Dict:
    options = {
        "target": args.root,
        "verbose": args.verbose,
        "debug": args.debug,
        "log": args.log,
        "add": not args.no_smt_add,
        "sub": not args.no_smt_sub,
        "mul": not args.no_smt_mul,
        "div": args.smt_div,
        "mod": args.smt_mod,
        "divByConst": args.smt_div_by_const,
        "modByConst": args.smt_mod_by_const,
        "expByConst": args.smt_exp_by_const,
        "timeout": args.solver_timeout_branching,
        "sym_jump": args.symbolic_jump,
        "print_steps": args.print_steps,
    }

    if args.width is not None:
        options["max_width"] = args.width

    if args.depth is not None:
        options["max_depth"] = args.depth

    if args.loop is not None:
        options["max_loop"] = args.loop

    return options


def mk_arrlen(args: argparse.Namespace) -> Dict[str, int]:
    arrlen = {}
    if args.array_lengths:
        for assign in [x.split("=") for x in args.array_lengths.split(",")]:
            name = assign[0].strip()
            size = assign[1].strip()
            arrlen[name] = int(size)
    return arrlen


def parse_build_out(args: argparse.Namespace) -> Dict:
    result = {}  # compiler version -> source filename -> contract name -> (json, type)

    out_path = os.path.join(args.root, args.forge_build_out)
    if not os.path.exists(out_path):
        raise FileNotFoundError(
            f"the build output directory `{out_path}` does not exist"
        )

    for sol_dirname in os.listdir(out_path):  # for each source filename
        if not sol_dirname.endswith(".sol"):
            continue

        sol_path = os.path.join(out_path, sol_dirname)
        if not os.path.isdir(sol_path):
            continue

        for json_filename in os.listdir(sol_path):  # for each contract name
            if not json_filename.endswith(".json"):
                continue
            if json_filename.startswith("."):
                continue

            json_path = os.path.join(sol_path, json_filename)
            with open(json_path, encoding="utf8") as f:
                json_out = json.load(f)

            compiler_version = json_out["metadata"]["compiler"]["version"]
            if compiler_version not in result:
                result[compiler_version] = {}
            if sol_dirname not in result[compiler_version]:
                result[compiler_version][sol_dirname] = {}
            contract_map = result[compiler_version][sol_dirname]

            contract_name = json_filename.split(".")[
                0
            ]  # cut off compiler version number as well

            contract_type = None
            for node in json_out["ast"]["nodes"]:
                if (
                    node["nodeType"] == "ContractDefinition"
                    and node["name"] == contract_name
                ):
                    abstract = "abstract " if node.get("abstract") else ""
                    contract_type = abstract + node["contractKind"]
                    break
            if contract_type is None:
                raise ValueError("no contract type", contract_name)

            if contract_name in contract_map:
                raise ValueError(
                    "duplicate contract names in the same file",
                    contract_name,
                    sol_dirname,
                )
            contract_map[contract_name] = (json_out, contract_type)

    return result


def main() -> int:
    main_start = timer()

    #
    # z3 global options
    #

    set_option(max_width=240)
    set_option(max_lines=10**8)
    # set_option(max_depth=1000)

    #
    # command line arguments
    #

    global args
    args = parse_args()

    if args.version:
        print(f"Halmos {metadata.version('halmos')}")
        return 0

    # quick bytecode execution mode
    if args.bytecode is not None:
        run_bytecode(args.bytecode)
        return 0

    #
    # compile
    #

    build_cmd = [
        "forge",  # shutil.which('forge')
        "build",
        "--root",
        args.root,
        "--extra-output",
        "storageLayout",
        "metadata",
    ]

    # run forge without capturing stdout/stderr
    build_exitcode = subprocess.run(build_cmd).returncode

    if build_exitcode:
        print(color_warn(f"build failed: {build_cmd}"))
        return 1

    try:
        build_out = parse_build_out(args)
    except Exception as err:
        print(color_warn(f"build output parsing failed: {err}"))
        return 1

    main_mid = timer()

    #
    # run
    #

    total_passed = 0
    total_failed = 0
    total_found = 0

    for compiler_version in sorted(build_out):
        build_out_map = build_out[compiler_version]
        for filename in sorted(build_out_map):
            for contract_name in sorted(build_out_map[filename]):
                if args.contract and args.contract != contract_name:
                    continue

                (contract_json, contract_type) = build_out_map[filename][contract_name]
                if contract_type != "contract":
                    continue

                hexcode = contract_json["deployedBytecode"]["object"]
                abi = contract_json["abi"]
                methodIdentifiers = contract_json["methodIdentifiers"]

                funsigs = [
                    funsig
                    for funsig in methodIdentifiers
                    if funsig.startswith(args.function)
                ]

                if funsigs:
                    total_found += len(funsigs)
                    print(
                        f"\nRunning {len(funsigs)} tests for {contract_json['ast']['absolutePath']}:{contract_name}"
                    )
                    contract_start = timer()

                    run_args = RunArgs(funsigs, hexcode, abi, methodIdentifiers)
                    enable_parallel = args.test_parallel and len(funsigs) > 1
                    num_passed, num_failed = (
                        run_parallel(run_args)
                        if enable_parallel
                        else run_sequential(run_args)
                    )

                    print(
                        f"Symbolic test result: {num_passed} passed; {num_failed} failed; time: {timer() - contract_start:0.2f}s"
                    )
                    total_passed += num_passed
                    total_failed += num_failed

    main_end = timer()

    if args.statistics:
        print(
            f"\n[time] total: {main_end - main_start:0.2f}s (build: {main_mid - main_start:0.2f}s, tests: {main_end - main_mid:0.2f}s)"
        )

    if total_found == 0:
        error_msg = f"Error: No tests with the prefix `{args.function}`"
        if args.contract is not None:
            error_msg += f" in {args.contract}"
        print(color_warn(error_msg))
        return 1

    # exitcode
    if total_failed == 0:
        return 0
    else:
        return 1


if __name__ == "__main__":
    sys.exit(main())
