# SPDX-License-Identifier: AGPL-3.0

import os
import sys
import subprocess
import uuid
import json
import re
import traceback

from argparse import Namespace
from dataclasses import dataclass, asdict
from importlib import metadata

from .pools import thread_pool, process_pool
from .sevm import *
from .utils import color_good, color_warn, hexify, NamedTimer
from .warnings import *
from .parser import mk_arg_parser
from .calldata import Calldata

StrModel = Dict[str, str]
AnyModel = UnionType[Model, StrModel]

arg_parser = mk_arg_parser()

# Python version >=3.8.14, >=3.9.14, >=3.10.7, or >=3.11
if hasattr(sys, "set_int_max_str_digits"):
    sys.set_int_max_str_digits(0)

# sometimes defaults to cp1252 on Windows, which can cause UnicodeEncodeError
if sys.stdout.encoding != "utf-8":
    sys.stdout.reconfigure(encoding="utf-8")


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
    cd: List,
    dyn_param_size: List[str],
    args: Namespace,
) -> None:
    # find function abi
    fun_abi = find_abi(abi, fun_info)

    # no parameters
    if len(fun_abi["inputs"]) == 0:
        return

    # generate symbolic ABI calldata
    calldata = Calldata(args, mk_arrlen(args), dyn_param_size)
    result = calldata.create(fun_abi)

    # TODO: use Contract abstraction for calldata
    wstore(cd, 4, result.size() // 8, result)


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


def mk_caller(args: Namespace) -> Address:
    if args.symbolic_msg_sender:
        return mk_addr("msg_sender")
    else:
        return con_addr(magic_address)


def mk_this() -> Address:
    return con_addr(magic_address + 1)


def mk_solver(args: Namespace):
    # quantifier-free bitvector + array theory; https://smtlib.cs.uiowa.edu/logics.shtml
    solver = SolverFor("QF_AUFBV")
    solver.set(timeout=args.solver_timeout_branching)
    return solver


def run_bytecode(hexcode: str, args: Namespace) -> List[Exec]:
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
        pgm=contract,
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
            warn(INTERNAL_ERROR, f"{mnemonic(opcode)} failed: {ex.error}")
        if args.print_states:
            print(f"# {idx+1} / {len(exs)}")
            print(ex)

    return exs


def deploy_test(
    creation_hexcode: str,
    deployed_hexcode: str,
    sevm: SEVM,
    args: Namespace,
    libs: Dict,
) -> Exec:
    this = mk_this()

    ex = sevm.mk_exec(
        code={this: Contract(b"")},
        storage={this: {}},
        balance=mk_balance(),
        block=mk_block(),
        calldata=[],
        callvalue=con(0),
        caller=mk_caller(args),
        this=this,
        pgm=None,  # to be added
        symbolic=False,
        solver=mk_solver(args),
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
    (exs, _, _) = sevm.run(ex)

    # sanity check
    if len(exs) != 1:
        raise ValueError(f"constructor: # of paths: {len(exs)}")
    ex = exs[0]
    if ex.failed:
        raise ValueError(f"constructor: failed: {ex.error}")
    if ex.current_opcode() not in [EVM.STOP, EVM.RETURN]:
        raise ValueError(f"constructor: failed: {ex.current_opcode()}: {ex.error}")

    # deployed bytecode
    deployed_bytecode = Contract(ex.output)
    ex.code[this] = deployed_bytecode
    ex.pgm = deployed_bytecode

    # reset vm state
    ex.pc = 0
    ex.st = State()
    ex.jumpis = {}
    ex.output = None
    ex.prank = Prank()

    return ex


def setup(
    creation_hexcode: str,
    deployed_hexcode: str,
    abi: List,
    setup_info: FunctionInfo,
    args: Namespace,
    libs: Dict,
) -> Exec:
    setup_timer = NamedTimer("setup")
    setup_timer.create_subtimer("decode")

    sevm = SEVM(mk_options(args))

    setup_ex = deploy_test(creation_hexcode, deployed_hexcode, sevm, args, libs)

    setup_timer.create_subtimer("run")

    setup_sig, setup_name, setup_selector = (
        setup_info.sig,
        setup_info.name,
        setup_info.selector,
    )
    if setup_sig:
        if args.verbose >= 1:
            print(f"Running {setup_sig}")

        wstore(setup_ex.calldata, 0, 4, BitVecVal(int(setup_selector, 16), 32))
        dyn_param_size = []  # TODO: propagate to run
        mk_calldata(abi, setup_info, setup_ex.calldata, dyn_param_size, args)

        (setup_exs_all, setup_steps, setup_logs) = sevm.run(setup_ex)

        if setup_logs.bounded_loops:
            warn(
                LOOP_BOUND,
                f"{setup_sig}: paths have not been fully explored due to the loop unrolling bound: {args.loop}",
            )
            if args.debug:
                print("\n".join(setup_logs.bounded_loops))

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


@dataclass(frozen=True)
class TestResult:
    name: str  # test function name
    exitcode: int  # 0: passed, 1: failed, 2: setup failed, ...
    num_models: int = None
    models: List[ModelWithContext] = None
    num_paths: Tuple[int, int, int] = None  # number of paths: [total, success, blocked]
    time: Tuple[int, int, int] = None  # time: [total, paths, models]
    num_bounded_loops: int = None  # number of incomplete loops


def run(
    setup_ex: Exec,
    abi: List,
    fun_info: FunctionInfo,
    args: Namespace,
) -> TestResult:
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

    timer = NamedTimer("time")
    timer.create_subtimer("paths")

    options = mk_options(args)
    sevm = SEVM(options)

    solver = SolverFor("QF_AUFBV")
    solver.set(timeout=args.solver_timeout_branching)
    solver.add(setup_ex.solver.assertions())

    (exs, steps, logs) = sevm.run(
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
            pgm=setup_ex.code[setup_ex.this],
            pc=0,
            st=State(),
            jumpis={},
            output=None,
            symbolic=args.symbolic_storage,
            prank=Prank(),  # prank is reset after setUp()
            #
            solver=solver,
            path=setup_ex.path.copy(),
            alias=setup_ex.alias.copy(),
            #
            log=setup_ex.log.copy(),
            cnts=deepcopy(setup_ex.cnts),
            sha3s=setup_ex.sha3s.copy(),
            storages=setup_ex.storages.copy(),
            balances=setup_ex.balances.copy(),
            calls=setup_ex.calls.copy(),
            failed=setup_ex.failed,
            error=setup_ex.error,
        )
    )

    timer.create_subtimer("models")

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

    no_counterexample = all(m.model is None for m in models)
    passed = no_counterexample and normal > 0 and len(stuck) == 0
    if args.error_unknown:
        passed = passed and all(m.result == unsat for m in models)
    passfail = color_good("[PASS]") if passed else color_warn("[FAIL]")

    timer.stop()
    time_info = timer.report(include_subtimers=args.statistics)

    # print result
    print(
        f"{passfail} {funsig} (paths: {normal}/{len(exs)}, {time_info}, bounds: [{', '.join(dyn_param_size)}])"
    )
    counterexamples = []
    for m in models:
        model, is_valid, index, result = m.model, m.is_valid, m.index, m.result
        if result == unsat:
            continue
        ex = exs[index]

        # model could be an empty dict here
        if model is not None:
            if is_valid:
                print(color_warn(f"Counterexample: {render_model(model)}"))
                counterexamples.append(model)
            elif args.print_potential_counterexample:
                warn(
                    COUNTEREXAMPLE_INVALID,
                    f"Counterexample (potentially invalid): {render_model(model)}",
                )
                counterexamples.append(model)
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
        warn(INTERNAL_ERROR, f"{mnemonic(opcode)} failed: {ex.error}")
        if args.print_blocked_states:
            print(f"# {idx+1} / {len(exs)}")
            print(ex)

    if logs.bounded_loops:
        warn(
            LOOP_BOUND,
            f"{funsig}: paths have not been fully explored due to the loop unrolling bound: {args.loop}",
        )
        if args.debug:
            print("\n".join(logs.bounded_loops))

    if logs.unknown_calls:
        warn(
            UNINTERPRETED_UNKNOWN_CALLS,
            f"{funsig}: unknown calls have been assumed to be static: {', '.join(logs.unknown_calls)}",
        )
        if args.debug:
            logs.print_unknown_calls()

    # print post-states
    if args.print_states:
        for idx, ex in enumerate(exs):
            print(f"# {idx+1} / {len(exs)}")
            print(ex)

    # log steps
    if args.log:
        with open(args.log, "w") as json_file:
            json.dump(steps, json_file)

    # return test result
    exitcode = 0 if passed else 1
    if args.minimal_json_output:
        return TestResult(funsig, exitcode, len(counterexamples))
    else:
        return TestResult(
            funsig,
            exitcode,
            len(counterexamples),
            counterexamples,
            (len(exs), normal, len(stuck)),
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
    setup_args: Namespace
    args: Namespace
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
        print(
            color_warn(
                f"Error: {fn_args.setup_info.sig} failed: {type(err).__name__}: {err}"
            )
        )
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
        print(f"{color_warn('[SKIP]')} {fn_args.fun_info.sig}")
        print(color_warn(f"{type(err).__name__}: {err}"))
        if args.debug:
            traceback.print_exc()
        return [TestResult(fn_args.fun_info.sig, 2)]

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

    args: Namespace
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
            extend_args(args, parse_devdoc(setup_info.sig, run_args.contract_json)),
            extend_args(args, parse_devdoc(fun_info.sig, run_args.contract_json)),
            libs,
        )
        for fun_info in fun_infos
    ]

    # dispatch to the shared process pool
    test_results = list(process_pool.map(setup_and_run_single, single_run_args))
    test_results = sum(test_results, [])  # flatten lists

    return test_results


def run_sequential(run_args: RunArgs) -> List[TestResult]:
    args = run_args.args
    setup_info = extract_setup(run_args.methodIdentifiers)

    try:
        setup_args = extend_args(
            args, parse_devdoc(setup_info.sig, run_args.contract_json)
        )
        setup_ex = setup(
            run_args.creation_hexcode,
            run_args.deployed_hexcode,
            run_args.abi,
            setup_info,
            setup_args,
            run_args.libs,
        )
    except Exception as err:
        print(
            color_warn(f"Error: {setup_info.sig} failed: {type(err).__name__}: {err}")
        )
        if args.debug:
            traceback.print_exc()
        return []

    test_results = []
    for funsig in run_args.funsigs:
        fun_info = FunctionInfo(
            funsig.split("(")[0], funsig, run_args.methodIdentifiers[funsig]
        )
        try:
            extended_args = extend_args(
                args, parse_devdoc(funsig, run_args.contract_json)
            )
            test_result = run(setup_ex, run_args.abi, fun_info, extended_args)
        except Exception as err:
            print(f"{color_warn('[SKIP]')} {funsig}")
            print(color_warn(f"{type(err).__name__}: {err}"))
            if args.debug:
                traceback.print_exc()
            test_results.append(TestResult(funsig, 2))
            continue

        test_results.append(test_result)

    return test_results


def extend_args(args: Namespace, more_opts: str) -> Namespace:
    if more_opts:
        new_args = deepcopy(args)
        arg_parser.parse_args(more_opts.split(), new_args)
        return new_args
    else:
        return args


@dataclass(frozen=True)
class GenModelArgs:
    args: Namespace
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
    return result == unknown or (result == sat and not is_model_valid(model))


def gen_model(args: Namespace, idx: int, ex: Exec) -> ModelWithContext:
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
        # sol2.set(timeout=args.solver_timeout_assertion)
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
    model: Optional[UnionType[Model, str]],
    idx: int,
    result: CheckSatResult,
    args: Namespace,
) -> ModelWithContext:
    if result == unsat:
        if args.verbose >= 1:
            print(f"  Invalid path; ignored (path id: {idx+1})")
        return ModelWithContext(None, None, idx, result)

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

        return ModelWithContext(model, is_valid, idx, result)

    else:
        if args.verbose >= 1:
            print(f"  Timeout (path id: {idx+1})")
        return ModelWithContext(None, None, idx, result)


def is_model_valid(model: AnyModel) -> bool:
    for decl in model:
        if str(decl).startswith("evm_"):
            return False
    return True


def to_str_model(model: Model, print_full_model: bool) -> StrModel:
    def select(var):
        name = str(var)
        return name.startswith("p_") or name.startswith("halmos_")

    select_model = filter(select, model) if not print_full_model else model
    return {str(decl): hexify(model[decl]) for decl in select_model}


def render_model(model: UnionType[str, StrModel]) -> str:
    if isinstance(model, str):
        return model

    formatted = [f"\n    {decl} = {hexify(val)}" for decl, val in model.items()]
    return "".join(sorted(formatted)) if formatted else "∅"


def mk_options(args: Namespace) -> Dict:
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
        "unknown_calls_return_size": args.return_size_of_unknown_calls,
        "ffi": args.ffi,
        "custom_storage_layout": args.custom_storage_layout,
    }

    if args.width is not None:
        options["max_width"] = args.width

    if args.depth is not None:
        options["max_depth"] = args.depth

    if args.loop is not None:
        options["max_loop"] = args.loop

    options["unknown_calls"] = []
    if args.uninterpreted_unknown_calls.strip():
        for x in args.uninterpreted_unknown_calls.split(","):
            options["unknown_calls"].append(int(x, 0))

    return options


def mk_arrlen(args: Namespace) -> Dict[str, int]:
    arrlen = {}
    if args.array_lengths:
        for assign in [x.split("=") for x in args.array_lengths.split(",")]:
            name = assign[0].strip()
            size = assign[1].strip()
            arrlen[name] = int(size)
    return arrlen


def parse_build_out(args: Namespace) -> Dict:
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

                compiler_version = json_out["metadata"]["compiler"]["version"]
                if compiler_version not in result:
                    result[compiler_version] = {}
                if sol_dirname not in result[compiler_version]:
                    result[compiler_version][sol_dirname] = {}
                contract_map = result[compiler_version][sol_dirname]

                # cut off compiler version number as well
                contract_name = json_filename.split(".")[0]

                contract_type = None
                for node in json_out["ast"]["nodes"]:
                    if (
                        node["nodeType"] == "ContractDefinition"
                        and node["name"] == contract_name
                    ):
                        abstract = "abstract " if node.get("abstract") else ""
                        contract_type = abstract + node["contractKind"]
                        natspec = node.get("documentation")
                        break
                if contract_type is None:
                    raise ValueError("no contract type", contract_name)

                if contract_name in contract_map:
                    raise ValueError(
                        "duplicate contract names in the same file",
                        contract_name,
                        sol_dirname,
                    )
                contract_map[contract_name] = (json_out, contract_type, natspec)
            except Exception as err:
                print(
                    color_warn(
                        f"Skipped {json_filename} due to parsing failure: {type(err).__name__}: {err}"
                    )
                )
                if args.debug:
                    traceback.print_exc()
                continue

    return result


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

    args = arg_parser.parse_args(_args)

    if args.version:
        print(f"Halmos {metadata.version('halmos')}")
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
        "--root",
        args.root,
        "--extra-output",
        "storageLayout",
        "metadata",
    ]

    # run forge without capturing stdout/stderr
    build_exitcode = subprocess.run(build_cmd).returncode

    if build_exitcode:
        print(color_warn(f"Build failed: {build_cmd}"))
        return MainResult(1)

    timer.create_subtimer("load")
    try:
        build_out = parse_build_out(args)
    except Exception as err:
        print(color_warn(f"Build output parsing failed: {type(err).__name__}: {err}"))
        if args.debug:
            traceback.print_exc()
        return MainResult(1)

    timer.create_subtimer("tests")

    #
    # run
    #

    total_passed = 0
    total_failed = 0
    total_found = 0
    test_results_map = {}

    for build_out_map, filename, contract_name in build_output_iterator(build_out):
        if args.contract and args.contract != contract_name:
            continue

        (contract_json, contract_type, natspec) = build_out_map[filename][contract_name]
        if contract_type != "contract":
            continue

        methodIdentifiers = contract_json["methodIdentifiers"]
        funsigs = [f for f in methodIdentifiers if f.startswith(args.function)]
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
        contract_args = extend_args(args, parse_natspec(natspec)) if natspec else args

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
        error_msg = f"Error: No tests with the prefix `{args.function}`"
        if args.contract is not None:
            error_msg += f" in {args.contract}"
        print(color_warn(error_msg))
        return MainResult(1)

    exitcode = 0 if total_failed == 0 else 1
    result = MainResult(exitcode, test_results_map)

    if args.json_output:
        with open(args.json_output, "w") as json_file:
            json.dump(asdict(result), json_file, indent=4)

    return result


# entrypoint for the `halmos` script
def main() -> int:
    return _main().exitcode


# entrypoint for `python -m halmos`
if __name__ == "__main__":
    sys.exit(main())
