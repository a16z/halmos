import os
import re
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from z3 import CheckSatResult, Solver, sat, unknown, unsat

from halmos.calldata import FunctionInfo
from halmos.config import Config as HalmosConfig
from halmos.constants import VERBOSITY_TRACE_COUNTEREXAMPLE, VERBOSITY_TRACE_PATHS
from halmos.logs import (
    COUNTEREXAMPLE_INVALID,
    COUNTEREXAMPLE_UNKNOWN,
    debug,
    error,
    warn,
    warn_code,
)
from halmos.processes import PopenExecutor, PopenFuture, TimeoutExpired
from halmos.sevm import Exec, SMTQuery
from halmos.utils import con, red, stringify


@dataclass
class ModelVariable:
    full_name: str
    variable_name: str
    solidity_type: str
    smt_type: str
    size_bits: int
    value: int


ModelVariables = dict[str, ModelVariable]

# Regular expression for capturing halmos variables
halmos_var_pattern = re.compile(
    r"""
    \(\s*define-fun\s+               # Match "(define-fun"
    \|?((?:halmos_|p_)[^ |]+)\|?\s+  # Capture either halmos_* or p_*, optionally wrapped in "|"
    \(\)\s+\(_\s+([^ ]+)\s+          # Capture the SMTLIB type (e.g., "BitVec 256")
    (\d+)\)\s+                       # Capture the bit-width or type argument
    (                                # Group for the value
        \#b[01]+                     # Binary value (e.g., "#b1010")
        |\#x[0-9a-fA-F]+             # Hexadecimal value (e.g., "#xFF")
        |\(_\s+bv\d+\s+\d+\)         # Decimal value (e.g., "(_ bv42 256)")
    )
    """,
    re.VERBOSE,
)


@dataclass(frozen=True)
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
    solver_outputs: list["SolverOutput"] = field(default_factory=list)

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
                model = PotentialModel(model=parse_model_str(stdout), is_valid=is_valid)
                return SolverOutput(sat, path_id, model=model)
            case _:
                return SolverOutput(unknown, path_id)


def parse_const_value(value: str) -> int:
    match value[:2]:
        case "#b":
            return int(value[2:], 2)
        case "#x":
            return int(value[2:], 16)
        case "bv":
            return int(value[2:])
        case _:
            # we may have a group like (_ bv123 256)
            tokens = value.split()
            for token in tokens:
                if token.startswith("bv"):
                    return int(token[2:])

    raise ValueError(f"unknown value format: {value}")


def _parse_halmos_var_match(match: re.Match) -> ModelVariable:
    full_name = match.group(1).strip()
    smt_type = f"{match.group(2)} {match.group(3)}"
    size_bits = int(match.group(3))
    value = parse_const_value(match.group(4))

    # Extract name and typename from the variable name
    parts = full_name.split("_")
    variable_name = parts[1]
    solidity_type = parts[2]

    return ModelVariable(
        full_name=full_name,
        variable_name=variable_name,
        solidity_type=solidity_type,
        smt_type=smt_type,
        size_bits=size_bits,
        value=value,
    )


def parse_model_str(smtlib_str: str) -> ModelVariables:
    """Expects a whole smtlib model output file, as produced by a solver
    in response to a `(check-sat)` + `(get-model)` command.

    Extracts halmos variables and returns them grouped by their full name"""

    model_variables: dict[str, ModelVariable] = {}

    # use a regex to find all the variables
    # for now we explicitly don't try to properly parse the smtlib output
    # because of idiosyncrasies of different solvers:
    # - ignores the initial sat/unsat on the first line
    # - ignores the occasional `(model)` command used by yices, stp, cvc4, etc.

    for match in halmos_var_pattern.finditer(smtlib_str):
        try:
            variable = _parse_halmos_var_match(match)
            model_variables[variable.full_name] = variable
        except Exception as e:
            error(f"error parsing smtlib string '{match.string.strip()}': {e}")
            raise e

    return model_variables


def parse_model_file(file_path: str) -> ModelVariables:
    with open(file_path) as file:
        return parse_model_str(file.read())


def parse_unsat_core(output: str) -> list[str] | None:
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

    # solver_timeout_assertion == 0 means no timeout,
    # which translates to timeout_seconds=None for subprocess.run
    timeout_seconds = t / 1000 if (t := args.solver_timeout_assertion) else None

    cmd = args.solver_command.split() + [smt2_filename]
    future = PopenFuture(cmd, timeout=timeout_seconds)

    # starts the subprocess asynchronously
    fun_ctx.solver_executor.submit(future)

    # block until the external solver returns, times out, is interrupted, fails, etc.
    try:
        stdout, stderr, returncode = future.result()
    except TimeoutExpired:
        return SolverOutput(result=unknown, path_id=path_ctx.path_id)

    # save solver stdout to file
    with open(f"{smt2_filename}.out", "w") as f:
        f.write(stdout)

    # save solver stderr to file (only if there is an error)
    if stderr:
        with open(f"{smt2_filename}.err", "w") as f:
            f.write(stderr)

    return SolverOutput.from_result(stdout, stderr, returncode, path_ctx)


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

    # keep track of the solver outputs, so that we can display PASS/FAIL/TIMEOUT/ERROR later
    fun_ctx.solver_outputs.append(solver_output)

    if result == unsat:
        if solver_output.unsat_core:
            fun_ctx.unsat_cores.append(solver_output.unsat_core)
        return

    # model could be an empty dict here, so compare to None explicitly
    if model is None:
        warn_code(COUNTEREXAMPLE_UNKNOWN, f"Counterexample: {result}")
        return

    if model.is_valid:
        print(red(f"Counterexample: {model}"))
        fun_ctx.valid_counterexamples.append(model)

        # we have a valid counterexample, so we are eligible for early exit
        if args.early_exit:
            debug(f"Shutting down {fun_ctx.info.name}'s solver executor")
            fun_ctx.solver_executor.shutdown(wait=False)
    else:
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
