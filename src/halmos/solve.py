# SPDX-License-Identifier: AGPL-3.0

import re
import shlex
import subprocess
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory
from types import MappingProxyType
from typing import Literal

from z3 import CheckSatResult, Solver, sat, unknown, unsat

from halmos.calldata import FunctionInfo
from halmos.config import Config as HalmosConfig
from halmos.logs import (
    debug,
    error,
    warn,
)
from halmos.processes import (
    ExecutorRegistry,
    PopenExecutor,
    PopenFuture,
)
from halmos.sevm import Address, Exec, SMTQuery
from halmos.utils import hexify

EXIT_TIMEDOUT = 124


# Type alias for directory used for dumping SMT files
DumpDirectory = TemporaryDirectory | Path


def dirname(dump_dir: DumpDirectory) -> str:
    """Get the directory name from a DumpDirectory."""
    match dump_dir:
        case TemporaryDirectory():
            return dump_dir.name
        case Path():
            return str(dump_dir)
        case _:
            raise ValueError(f"Unexpected dump directory type: {type(dump_dir)}")


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


@dataclass(frozen=True, slots=True)
class PotentialModel:
    model: ModelVariables
    is_valid: bool

    def __str__(self) -> str:
        formatted = []
        for v in self.model.values():
            # TODO: parse type and render accordingly
            formatted.append(f"\n    {v.full_name} = {hexify(v.value)}")
        return "".join(sorted(formatted)) if formatted else "∅"


@dataclass(frozen=True, slots=True)
class InvariantTestingContext:
    # explicitly included targets
    target_senders: frozenset[Address]
    target_contracts: frozenset[Address]
    target_selectors: MappingProxyType[Address, frozenset[bytes]]

    # explicitly excluded targets
    excluded_senders: frozenset[Address]
    excluded_contracts: frozenset[Address]
    excluded_selectors: MappingProxyType[Address, frozenset[bytes]]

    # whether to print debug information
    debug: bool = False

    @staticmethod
    def empty() -> "InvariantTestingContext":
        return empty_invariant_testing_context


empty_invariant_testing_context = InvariantTestingContext(
    target_senders=frozenset(),
    target_contracts=frozenset(),
    target_selectors=MappingProxyType({}),  # read-only empty dict
    excluded_senders=frozenset(),
    excluded_contracts=frozenset(),
    excluded_selectors=MappingProxyType({}),
)


@dataclass(frozen=True, slots=True)
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

    # note: build_out_map is shared across all contracts compiled using the same compiler version
    # so in principle, we could consider having another context, say CompileUnitContext, and put build_out_map there
    build_out_map: dict

    # map from depth to frontier states
    frontier_states: dict[int, list[Exec]] = field(default_factory=dict)

    # set of visited state ids, to be updated during the invariant testing run
    visited: set[bytes] = field(default_factory=set)

    # the function info for the invariant test
    probes_reported: set[FunctionInfo] = field(default_factory=set)

    # the invariant testing context for this contract
    # the empty context is used as a placeholder, it can be set later
    inv_ctx: InvariantTestingContext = field(
        default_factory=InvariantTestingContext.empty
    )

    def set_invariant_testing_context(self, ctx: InvariantTestingContext) -> None:
        if self.inv_ctx != InvariantTestingContext.empty():
            raise ValueError("invariant testing context already set")

        # bypass the frozen dataclass check
        object.__setattr__(self, "inv_ctx", ctx)


@dataclass(frozen=True)
class SolvingContext:
    # directory for dumping solver files
    dump_dir: DumpDirectory

    # shared solver executor for all paths in the same function
    executor: PopenExecutor = field(default_factory=PopenExecutor)

    # list of unsat cores
    unsat_cores: list[list] = field(default_factory=list)


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

    # optional max call depth for frontier states (for invariant testing)
    max_call_depth: int = 0

    # function-level solving context
    # the FunctionContext initializes and owns the SolvingContext
    solving_ctx: SolvingContext = field(init=False)

    # function-level thread pool that drives assertion solving
    thread_pool: ThreadPoolExecutor = field(init=False)

    # list of solver outputs for this function
    solver_outputs: list["SolverOutput"] = field(default_factory=list)

    # list of valid counterexamples for this function
    valid_counterexamples: list[PotentialModel] = field(default_factory=list)

    # list of potentially invalid counterexamples for this function
    invalid_counterexamples: list[PotentialModel] = field(default_factory=list)

    # map from path id to trace and call sequence
    traces: dict[int, str] = field(default_factory=dict)
    call_sequences: dict[int, str] = field(default_factory=dict)

    # map from path id to execution
    exec_cache: dict[int, Exec] = field(default_factory=dict)

    def __post_init__(self):
        args = self.args

        # create a directory for dumping solver files
        prefix = (
            f"{self.info.name}-"
            if self.info.name
            else f"{self.contract_ctx.name}-constructor-"
        )

        if args.dump_smt_directory:
            # use custom directory specified by user
            custom_dir = Path(args.dump_smt_directory)

            # create the directory if it doesn't exist
            custom_dir.mkdir(parents=True, exist_ok=True)

            # create a subdirectory with the prefix for this function/contract
            function_dir = custom_dir / prefix.rstrip("-")
            function_dir.mkdir(parents=True, exist_ok=True)

            dump_dir = function_dir

            if args.verbose >= 1 or args.dump_smt_queries:
                print(f"Generating SMT queries in {function_dir}")
        else:
            # use temporary directory (existing behavior)
            # if the user explicitly enabled dumping, we don't want to delete the directory on exit
            delete = not self.args.dump_smt_queries

            # ideally we would pass `delete=delete` to the constructor, but it's in >=3.12
            temp_dir = TemporaryDirectory(prefix=prefix, ignore_cleanup_errors=True)

            # If user wants to keep the files, prevent cleanup on exit
            if not delete:
                temp_dir._finalizer.detach()

            dump_dir = temp_dir

            if args.verbose >= 1 or args.dump_smt_queries:
                print(f"Generating SMT queries in {temp_dir.name}")

        solving_ctx = SolvingContext(dump_dir=dump_dir)
        object.__setattr__(self, "solving_ctx", solving_ctx)

        thread_pool = ThreadPoolExecutor(
            max_workers=self.args.solver_threads,
            thread_name_prefix=f"{self.info.name}-",
        )
        object.__setattr__(self, "thread_pool", thread_pool)

        # register the solver executor to be shutdown on exit
        ExecutorRegistry().register(solving_ctx.executor)

    def append_unsat_core(self, unsat_core: list[str]) -> None:
        self.solving_ctx.unsat_cores.append(unsat_core)


@dataclass(frozen=True)
class PathContext:
    args: HalmosConfig
    path_id: int
    solving_ctx: SolvingContext
    query: SMTQuery
    is_refined: bool = False

    @property
    def dump_file(self) -> Path:
        refined_str = ".refined" if self.is_refined else ""
        filename = f"{self.path_id}{refined_str}.smt2"

        return Path(dirname(self.solving_ctx.dump_dir)) / filename

    def refine(self) -> "PathContext":
        return PathContext(
            args=self.args,
            path_id=self.path_id,
            solving_ctx=self.solving_ctx,
            query=refine(self.query),
            is_refined=True,
        )


@dataclass(frozen=True, slots=True)
class SolverOutput:
    # solver result (sat, unsat, unknown, err)
    result: CheckSatResult | Literal["err"]

    # solver return code
    returncode: int

    # we don't backlink to the parent path context to avoid extra
    # references to Exec objects past the lifetime of the path
    path_id: int

    # solver model
    model: PotentialModel | None = None

    # optional unsat core
    unsat_core: list[str] | None = None

    # solver error
    error: str | None = None

    @staticmethod
    def from_result(
        stdout: str, stderr: str, returncode: int, path_ctx: PathContext
    ) -> "SolverOutput":
        # extract the first line (we expect sat/unsat/unknown)
        newline_idx = stdout.find("\n")
        first_line = stdout[:newline_idx] if newline_idx != -1 else stdout

        args, path_id = path_ctx.args, path_ctx.path_id
        if args.verbose >= 1:
            debug(f"    {first_line}")

        match first_line:
            case "unsat":
                unsat_core = parse_unsat_core(stdout) if args.cache_solver else None
                return SolverOutput(unsat, returncode, path_id, unsat_core=unsat_core)
            case "sat":
                is_valid = is_model_valid(stdout)
                model = PotentialModel(model=parse_model_str(stdout), is_valid=is_valid)
                return SolverOutput(sat, returncode, path_id, model=model)
            case "unknown":
                return SolverOutput(unknown, returncode, path_id)
            case _:
                return SolverOutput("err", returncode, path_id, error=stderr)


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
    args, query, dump_file = path_ctx.args, path_ctx.query, path_ctx.dump_file

    if args.verbose >= 1:
        debug(f"Writing SMT query to {dump_file}")

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

        dump_file.write_text(
            "(set-option :produce-unsat-cores true)\n"
            "(set-logic QF_AUFBV)\n"
            f"{query.smtlib}\n"
            f"{named_assertions}"
            "(check-sat)\n"
            "(get-model)\n"
            "(get-unsat-core)\n"
        )

    else:
        dump_file.write_text(
            f"(set-logic QF_AUFBV)\n{query.smtlib}\n(check-sat)\n(get-model)\n"
        )


def is_model_valid(solver_stdout: str) -> bool:
    # TODO: evaluate the path condition against the given model after excluding f_evm_* symbols,
    #       since the f_evm_* symbols may still appear in valid models.

    return "f_evm_" not in solver_stdout


def solve_low_level(path_ctx: PathContext) -> SolverOutput:
    """Invokes an external solver process to solve the given query.

    Can raise TimeoutError or some Exception raised during execution"""

    args, smt2_filename = path_ctx.args, str(path_ctx.dump_file)

    # make sure the smt2 file has been written
    dump(path_ctx)

    solver_command = args.resolved_solver_command + [smt2_filename]
    if args.verbose >= 1:
        print("  Checking with external solver process")
        print(f"    {shlex.join(solver_command)} > {smt2_filename}.out")

    # solver_timeout_assertion == 0 means no timeout,
    # which translates to timeout_seconds=None for subprocess.run
    timeout_seconds = t if (t := args.solver_timeout_assertion) else None
    future = PopenFuture(solver_command, timeout=timeout_seconds)

    # starts the subprocess asynchronously
    path_ctx.solving_ctx.executor.submit(future)

    # block until the external solver returns, times out, is interrupted, fails, etc.
    try:
        stdout, stderr, returncode = future.result()
    except subprocess.TimeoutExpired:
        return SolverOutput(
            result=unknown, returncode=EXIT_TIMEDOUT, path_id=path_ctx.path_id
        )

    # save solver stdout to file
    with open(f"{smt2_filename}.out", "w") as f:
        f.write(stdout)

    # save solver stderr to file (only if there is an error)
    if stderr:
        with open(f"{smt2_filename}.err", "w") as f:
            f.write(stderr)

    return SolverOutput.from_result(stdout, stderr, returncode, path_ctx)


def solve_end_to_end(ctx: PathContext) -> SolverOutput:
    """Synchronously resolves a query in a given context, which may result in 0, 1 or multiple solver invocations.

    - may result in 0 invocations if the query contains a known unsat core (hence the need for the context)
    - may result in exactly 1 invocation if the query is unsat, or sat with a valid model
    - may result in multiple invocations if the query is sat and the model is invalid (needs refinement)

    If this produces a model, it _should_ be valid.
    """
    path_id, query = ctx.path_id, ctx.query

    verbose = print if ctx.args.verbose >= 1 else lambda *args, **kwargs: None
    verbose(f"Checking path condition {path_id=}")

    # if the query contains an unsat-core, it is unsat; no need to run the solver
    if check_unsat_cores(query, ctx.solving_ctx.unsat_cores):
        verbose("  Already proven unsat")
        return SolverOutput(unsat, 0, path_id)

    solver_output = solve_low_level(ctx)
    result, model = solver_output.result, solver_output.model

    # if the ctx is already refined, we don't need to solve again
    if result == sat and not model.is_valid and not ctx.is_refined:
        verbose("  Checking again with refinement")

        refined_ctx = ctx.refine()

        if refined_ctx.query.smtlib != query.smtlib:
            # note that check_unsat_cores cannot return true for the refined query, because it relies on only
            # constraint ids, which don't change after refinement
            # therefore we can skip the unsat core check in solve_end_to_end and go directly to solve_low_level
            return solve_low_level(refined_ctx)
        else:
            verbose("    Refinement did not change the query, no need to solve again")

    return solver_output


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
