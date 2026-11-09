# SPDX-License-Identifier: AGPL-3.0

import re
import shlex
import subprocess
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from dataclasses import dataclass, field, replace
from pathlib import Path
from tempfile import TemporaryDirectory
from types import MappingProxyType
from typing import Literal

from eth_hash.auto import keccak
from z3 import CheckSatResult, Solver, is_app, sat, unknown, unsat

from dolmos.calldata import FunctionInfo
from dolmos.config import Config as DolmosConfig
from dolmos.logs import (
    debug,
    error,
    warn,
)
from dolmos.pcex import PcexState
from dolmos.processes import (
    ExecutorRegistry,
    PopenExecutor,
    PopenFuture,
)
from dolmos.sevm import Address, Exec, SMTQuery
from dolmos.utils import f_sha3_name, hexify, is_bv_value, is_f_sha3_name

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

# Regular expression for capturing dolmos variables
dolmos_var_pattern = re.compile(
    r"""
    \(\s*define-fun\s+               # Match "(define-fun"
    \|?((?:dolmos_|p_)[^ |]+)\|?\s+  # Capture either dolmos_* or p_*, optionally wrapped in "|"
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


def describe_solver_error(stderr: str, returncode: int | None, args=None) -> str:
    """
    A readable description of a solver failure (halmos#580): a negative return code
    means that the solver process was killed by a signal, e.g. -4 (SIGILL) when the
    solver binary uses CPU instructions that this machine does not support, or -9
    (SIGKILL) when it ran out of memory. The solver's stderr, often empty in that
    case, is kept.
    """
    import signal

    stderr = (stderr or "").strip()
    solver = None
    if args is not None:
        with suppress(Exception):
            solver = args.solver_command or args.solver

    parts = []
    if returncode is not None and returncode < 0:
        try:
            name = signal.Signals(-returncode).name
        except ValueError:
            name = f"signal {-returncode}"
        reason = {
            "SIGILL": "illegal instruction: the solver binary is probably built for "
            "another CPU; try another solver with --solver, or a build of this one "
            "for your machine",
            "SIGKILL": "killed, e.g. by the system when it ran out of memory; see "
            "--solver-max-memory",
            "SIGSEGV": "segmentation fault in the solver",
            "SIGABRT": "the solver aborted",
        }.get(name, "the solver was killed by a signal")
        parts.append(f"solver terminated by {name} ({reason})")
    elif returncode:
        parts.append(f"solver exited with code {returncode}")
    else:
        parts.append("unexpected solver output")

    if solver:
        parts.append(f"solver: {solver}")
    if stderr:
        parts.append(f"stderr: {stderr}")
    return "; ".join(parts)


@dataclass(frozen=True, slots=True)
class PotentialModel:
    model: ModelVariables
    is_valid: bool

    def __str__(self) -> str:
        return self.render()

    def render(self, address_hints: dict[int, str] | None = None) -> str:
        """
        The values of the model, one per line. Addresses that are known, e.g. labeled
        with vm.label or where a contract is deployed, are annotated (halmos#447).
        """
        formatted = []
        for v in self.model.values():
            # TODO: parse type and render accordingly
            line = f"\n    {v.full_name} = {hexify(v.value)}"
            hint = address_hints.get(v.value) if address_hints else None
            if hint and is_address_variable(v):
                line += f" ({hint})"
            formatted.append(line)
        return "".join(sorted(formatted)) if formatted else "∅"


def is_address_variable(v: ModelVariable) -> bool:
    """whether a model variable holds an address, from its size or its name"""
    return v.size_bits == 160 or "_address_" in v.full_name


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

    # targetInterfaces(): the artifacts whose ABI is used for an address (halmos#553)
    target_interfaces: MappingProxyType[Address, tuple[str, ...]] = field(
        default_factory=lambda: MappingProxyType({})
    )

    # ERC-1967 proxies found after setUp: proxy -> implementation (halmos#553)
    proxy_implementations: MappingProxyType[Address, Address] = field(
        default_factory=lambda: MappingProxyType({})
    )

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
    args: DolmosConfig

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
    args: DolmosConfig

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

    # shown and hidden counterexamples, with --pretty-counterexamples
    pcex: PcexState = field(default_factory=PcexState)

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
    args: DolmosConfig
    path_id: int
    solving_ctx: SolvingContext
    query: SMTQuery
    is_refined: bool = False

    # symbolic keccak preimages of the path, as (bitsize, smtlib term); see mk_sha3_args()
    sha3_args: tuple[tuple[int, str], ...] = ()

    # applications of the EXP abstraction in the path, checked against the real
    # exponentiation with --pretty-counterexamples; see mk_exp_apps() and refine_exp()
    exp_apps: "ExpApps | None" = None

    # distinguishes the query files of keccak refinement rounds
    suffix: str = ""

    @property
    def dump_file(self) -> Path:
        refined_str = ".refined" if self.is_refined else ""
        filename = f"{self.path_id}{refined_str}{self.suffix}.smt2"

        return Path(dirname(self.solving_ctx.dump_dir)) / filename

    def refine(self) -> "PathContext":
        return PathContext(
            args=self.args,
            path_id=self.path_id,
            solving_ctx=self.solving_ctx,
            query=refine(self.query),
            is_refined=True,
            sha3_args=self.sha3_args,
            exp_apps=self.exp_apps,
            suffix=self.suffix,
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

    # input query file path
    query_file: str

    # solver model
    model: PotentialModel | None = None

    # optional unsat core
    unsat_core: list[str] | None = None

    # solver error
    error: str | None = None

    # why the model is potentially invalid, when known (shown by --pretty-counterexamples)
    invalid_reason: str | None = None

    @staticmethod
    def from_result(
        stdout: str, stderr: str, returncode: int, path_ctx: PathContext
    ) -> "SolverOutput":
        # extract the first line (we expect sat/unsat/unknown)
        newline_idx = stdout.find("\n")
        first_line = stdout[:newline_idx] if newline_idx != -1 else stdout

        args, path_id = path_ctx.args, path_ctx.path_id
        query_file = str(path_ctx.dump_file)

        if args.verbose >= 1:
            debug(f"    {first_line}")

        match first_line:
            case "unsat":
                unsat_core = parse_unsat_core(stdout) if args.cache_solver else None
                return SolverOutput(
                    unsat, returncode, path_id, query_file, unsat_core=unsat_core
                )
            case "sat":
                is_valid = is_model_valid(stdout)
                model = PotentialModel(model=parse_model_str(stdout), is_valid=is_valid)
                return SolverOutput(sat, returncode, path_id, query_file, model=model)
            case "unknown":
                return SolverOutput(unknown, returncode, path_id, query_file)
            case _:
                return SolverOutput(
                    "err",
                    returncode,
                    path_id,
                    query_file,
                    error=describe_solver_error(stderr, returncode, args),
                )

    @staticmethod
    def from_error(
        error: Exception | str,
        path_id: int,
        query_file: str,
        returncode: int = -1,
    ) -> "SolverOutput":
        return SolverOutput(
            result="err",
            returncode=returncode,
            path_id=path_id,
            query_file=query_file,
            error=str(error),
        )


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


def _parse_dolmos_var_match(match: re.Match) -> ModelVariable:
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


# the model format of solvers that answer (get-model) with equalities, e.g. yices
# with `--smt2-model-format` off, or the models saved in smt files (halmos#449):
#   (= p_x_uint256_8d8a5a6_00 #b0101...)
dolmos_eq_pattern = re.compile(
    r"""
    \(\s*=\s+
    \|?((?:dolmos_|p_)[^ |()]+)\|?\s+  # the variable, optionally wrapped in "|"
    (                                # its value
        \#b[01]+
        |\#x[0-9a-fA-F]+
        |\(_\s+bv\d+\s+\d+\)
    )
    \s*\)
    """,
    re.VERBOSE,
)


def _const_size(value: str) -> int:
    """bit size of a bitvector literal: #b..., #x... or (_ bvN size)"""
    if value.startswith("#b"):
        return len(value) - 2
    if value.startswith("#x"):
        return 4 * (len(value) - 2)
    return int(value.strip("()").split()[-1])


def _parse_dolmos_eq_match(match: re.Match) -> ModelVariable:
    full_name = match.group(1).strip()
    value_str = match.group(2)
    size_bits = _const_size(value_str)
    parts = full_name.split("_")
    return ModelVariable(
        full_name=full_name,
        variable_name=parts[1],
        solidity_type=parts[2],
        smt_type=f"BitVec {size_bits}",
        size_bits=size_bits,
        value=parse_const_value(value_str),
    )


def parse_model_str(smtlib_str: str) -> ModelVariables:
    """Expects a whole smtlib model output file, as produced by a solver
    in response to a `(check-sat)` + `(get-model)` command.

    Extracts dolmos variables and returns them grouped by their full name"""

    model_variables: dict[str, ModelVariable] = {}

    # use a regex to find all the variables
    # for now we explicitly don't try to properly parse the smtlib output
    # because of idiosyncrasies of different solvers:
    # - ignores the initial sat/unsat on the first line
    # - ignores the occasional `(model)` command used by yices, stp, cvc4, etc.

    for match in dolmos_var_pattern.finditer(smtlib_str):
        try:
            variable = _parse_dolmos_var_match(match)
            model_variables[variable.full_name] = variable
        except Exception as e:
            error(f"error parsing smtlib string '{match.string.strip()}': {e}")
            raise e

    # models made of equalities instead of define-fun (halmos#449)
    for match in dolmos_eq_pattern.finditer(smtlib_str):
        try:
            variable = _parse_dolmos_eq_match(match)
            model_variables.setdefault(variable.full_name, variable)
        except Exception as e:
            error(f"error parsing smtlib string '{match.group(0).strip()}': {e}")
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
            result=unknown,
            returncode=EXIT_TIMEDOUT,
            path_id=path_ctx.path_id,
            query_file=smt2_filename,
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
    """Solves the given query, then checks the keccak values the model relies on (see refine_keccak)."""
    if ctx.exp_apps:
        return solve_with_exp_refinement(ctx)

    if not ctx.sha3_args or ctx.args.keccak_refinement_rounds <= 0:
        return _solve_end_to_end(ctx)

    # expose the keccak preimages in the model with definitional (hence unsat-core neutral) constraints
    ctx = replace(
        ctx,
        query=SMTQuery(
            ctx.query.smtlib + sha3_arg_decls(ctx.sha3_args), ctx.query.assertions
        ),
    )
    solver_output = _solve_end_to_end(ctx)
    return refine_keccak(ctx, solver_output)


def _solve_end_to_end(ctx: PathContext) -> SolverOutput:
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
        return SolverOutput(unsat, 0, path_id, str(ctx.dump_file))

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


# keccak refinement (a16z/halmos#562)
#
# keccak256 is modeled as uninterpreted functions f_sha3_N, constrained only by the
# injectivity and range axioms, and by the concrete values of hashes of concrete data.
# A model may thus assign to a symbolic preimage x a hash value f_sha3_N(x) that differs
# from the real keccak256(x), e.g. the solver may pick x = 0 and "decide" that its hash
# is the key of a storage entry written in setUp. Such a counterexample does not replay.
#
# When the query is sat, the value of every symbolic preimage is read from the model, and
# the real hashes of these values are asserted, `f_sha3_N(v) == keccak256(v)`. These facts
# are true of the real hash function, so the refined query keeps every real counterexample:
# - if the model agrees with the real hashes, the counterexample is kept as is;
# - otherwise the query is solved again with the new facts: unsat means that no counterexample
#   exists under the real hash values (modulo the usual keccak assumptions), and a new model is
#   checked again, up to --keccak-refinement-rounds times; a model that still disagrees is
#   reported as potentially invalid.

SHA3_ARG_PREFIX = "sha3arg_"

sha3_arg_pattern = re.compile(
    rf"\(\s*define-fun\s+\|?({SHA3_ARG_PREFIX}\d+)\|?\s+\(\)\s+\(_\s+BitVec\s+(\d+)\)\s+"
    r"(#x[0-9a-fA-F]+|#b[01]+|\(_\s+bv\d+\s+\d+\))\s*\)"
)

MAX_SHA3_ARGS = 64


def mk_sha3_args(sha3s) -> tuple[tuple[int, str], ...]:
    """
    Returns the symbolic keccak preimages registered in the given KeccakRegistry, as
    (bitsize, smtlib term) pairs. Strings only: the result crosses thread boundaries.
    """
    result = []
    for expr in sha3s:
        if expr.num_args() != 1 or not is_f_sha3_name(expr.decl().name()):
            continue
        data = expr.arg(0)
        if is_bv_value(data):
            continue
        result.append((data.size(), data.sexpr()))
        if len(result) >= MAX_SHA3_ARGS:
            break
    return tuple(result)


def sha3_arg_decls(sha3_args) -> str:
    return "".join(
        f"(declare-fun {SHA3_ARG_PREFIX}{i} () (_ BitVec {size}))\n"
        f"(assert (= {SHA3_ARG_PREFIX}{i} {term}))\n"
        for i, (size, term) in enumerate(sha3_args)
    )


def parse_sha3_arg_values(solver_stdout: str) -> dict[int, tuple[int, int]]:
    """Returns {index: (bitsize, value)} for the sha3arg_* constants of the model"""
    values = {}
    for match in sha3_arg_pattern.finditer(solver_stdout):
        index = int(match.group(1)[len(SHA3_ARG_PREFIX) :])
        values[index] = (int(match.group(2)), parse_const_value(match.group(3)))
    return values


def keccak_fact(size: int, value: int) -> tuple[str, int] | None:
    """Returns the assertion `f_sha3_<size>(value) == keccak256(value)`, and the hash"""
    hash_value = int.from_bytes(keccak(value.to_bytes(size // 8, "big")), "big")

    # outside of the range assumed for hash values; see Exec.sha3_data()
    if hash_value == 0 or hash_value > 2**256 - 2**64:
        return None

    fact = f"(assert (= ({f_sha3_name(size)} (_ bv{value} {size})) (_ bv{hash_value} 256)))\n"
    return fact, hash_value


def refine_keccak(ctx: PathContext, solver_output: SolverOutput) -> SolverOutput:
    verbose = print if ctx.args.verbose >= 1 else lambda *args, **kwargs: None

    facts: dict[tuple[int, int], str] = {}
    base_smtlib = ctx.query.smtlib
    max_rounds = ctx.args.keccak_refinement_rounds

    for round in range(max_rounds + 1):
        result, model = solver_output.result, solver_output.model
        if result != sat or model is None or not model.is_valid:
            return solver_output

        try:
            with open(f"{solver_output.query_file}.out") as f:
                values = parse_sha3_arg_values(f.read())
        except OSError:
            return solver_output

        new_facts = {}
        consistent = True
        for size, value in values.values():
            if size % 8 or (size, value) in facts:
                continue
            fact = keccak_fact(size, value)
            if fact is None:
                consistent = False
                continue
            new_facts[size, value] = fact[0]

        if not new_facts:
            if consistent:
                return solver_output
            break

        if round == max_rounds:
            break

        facts.update(new_facts)
        verbose(
            f"  Checking again with {len(facts)} keccak value(s) (round {round + 1})"
        )

        refined_ctx = replace(
            ctx,
            query=SMTQuery(base_smtlib + "".join(facts.values()), ctx.query.assertions),
            suffix=f".keccak{round + 1}",
        )
        last_sat_output = solver_output
        solver_output = solve_low_level(refined_ctx)

        # an unsat core of the refined query may depend on the (unnamed) keccak facts,
        # so it cannot be reused for other queries
        if solver_output.unsat_core is not None:
            solver_output = replace(solver_output, unsat_core=None)

        # if the refined query cannot be decided (timeout, solver error), keep the last
        # counterexample rather than dropping it: only unsat proves its absence
        if solver_output.result not in (sat, unsat):
            verbose(f"  Refined query result: {solver_output.result}")
            solver_output = last_sat_output
            break

    # the model still relies on keccak values that may not exist
    verbose("  Keccak values of the model are not consistent with keccak256")
    potential_model = PotentialModel(model=solver_output.model.model, is_valid=False)
    return replace(
        solver_output, model=potential_model, invalid_reason=KECCAK_INVALID_REASON
    )


KECCAK_INVALID_REASON = (
    "relies on keccak256 values that differ from the real hash function "
    "(rerun with a larger --keccak-refinement-rounds)"
)


# EXP refinement (a16z/halmos#280), with --pretty-counterexamples
#
# EXP is modeled by the uninterpreted function f_evm_exp_256 when the exponent is symbolic,
# or when it is a constant above --smt-exp-by-const and the base is symbolic. A model may
# thus give `x ** 3` any value, and the counterexample is only reported as "potentially
# invalid", without saying why.
#
# With --pretty-counterexamples, each application `r = f_evm_exp_256(b, e)` of the path and
# its operands are exposed in the model, and compared with the real exponentiation:
# - if `r == b ** e mod 2**256` for every application, the model does not depend on the
#   abstraction, and the counterexample is valid;
# - otherwise the query is solved again with facts that hold for the real EXP, so that every
#   real counterexample is kept, and unsat proves that there is none:
#   - exact encodings, added once: a constant exponent is expanded by square and multiply,
#     and a constant base is tabulated over the exponents below 256 (an even base is then
#     exact, as b ** e == 0 mod 2**256 for e >= 256);
#   - the real value at the operands of each disagreeing application, `f(b, e) == b ** e`;
#   up to PCEX_EXP_REFINEMENT_ROUNDS times. Keccak values are checked in the same loop
#   (see refine_keccak), with --keccak-refinement-rounds additional rounds.
# A model that still disagrees is reported as potentially invalid, with the reason.

EXP_NAME = "f_evm_exp_256"
PCEX_EXP_REFINEMENT_ROUNDS = 3
MAX_EXP_APPS = 128

# constant exponents up to this bound are expanded by square and multiply
MAX_EXPANDED_EXPONENT = 2**64

WORD_MODULUS = 2**256

exp_arg_pattern = re.compile(
    r"\(\s*define-fun\s+\|?pcex_exp([ber])_(\d+)\|?\s+\(\)\s+\(_\s+BitVec\s+256\)\s+"
    r"(#x[0-9a-fA-F]+|#b[01]+|\(_\s+bv\d+\s+\d+\))\s*\)"
)

abstraction_name_pattern = re.compile(r"f_evm_[a-z]+_\d+")

UNDECIDED_REASON = (
    "the refined query could not be decided "
    "(rerun with a larger --solver-timeout-assertion)"
)


@dataclass(frozen=True)
class ExpApp:
    """An application of the EXP abstraction, as smtlib terms (no z3 object: crosses threads)"""

    base: str
    exponent: str

    # values of the operands, when they are constants
    base_value: int | None = None
    exponent_value: int | None = None

    def describe(self) -> str:
        base = "x" if self.base_value is None else str(self.base_value)
        exponent = "y" if self.exponent_value is None else str(self.exponent_value)
        return f"{base} ** {exponent}"


@dataclass(frozen=True)
class ExpApps:
    apps: tuple[ExpApp, ...] = ()

    # false if the path has more applications than MAX_EXP_APPS
    complete: bool = True

    def __bool__(self) -> bool:
        return bool(self.apps)

    def __len__(self) -> int:
        return len(self.apps)


def mk_exp_apps(conditions) -> ExpApps:
    """Returns the applications of the EXP abstraction in the given path conditions"""
    apps: dict[tuple[int, int], ExpApp] = {}
    complete = True
    visited = set()
    stack = list(conditions)
    while stack:
        expr = stack.pop()
        expr_id = expr.get_id()
        if expr_id in visited:
            continue
        visited.add(expr_id)

        if not is_app(expr):
            continue

        if expr.num_args() == 2 and expr.decl().name() == EXP_NAME:
            base, exponent = expr.arg(0), expr.arg(1)
            key = (base.get_id(), exponent.get_id())
            if key not in apps:
                if len(apps) >= MAX_EXP_APPS:
                    complete = False
                else:
                    apps[key] = ExpApp(
                        base=base.sexpr(),
                        exponent=exponent.sexpr(),
                        base_value=base.as_long() if is_bv_value(base) else None,
                        exponent_value=(
                            exponent.as_long() if is_bv_value(exponent) else None
                        ),
                    )

        stack.extend(expr.children())

    return ExpApps(tuple(apps.values()), complete)


def exp_names(i: int) -> tuple[str, str, str]:
    """names of the constants holding the base, exponent and result of the i-th application"""
    return f"pcex_expb_{i}", f"pcex_expe_{i}", f"pcex_expr_{i}"


def exp_arg_decls(apps: ExpApps) -> str:
    result = []
    for i, app in enumerate(apps.apps):
        b, e, r = exp_names(i)
        result.append(
            f"(declare-fun {b} () (_ BitVec 256))\n"
            f"(assert (= {b} {app.base}))\n"
            f"(declare-fun {e} () (_ BitVec 256))\n"
            f"(assert (= {e} {app.exponent}))\n"
            f"(declare-fun {r} () (_ BitVec 256))\n"
            f"(assert (= {r} ({EXP_NAME} {b} {e})))\n"
        )
    return "".join(result)


def parse_exp_arg_values(solver_stdout: str) -> dict[int, dict[str, int]]:
    """Returns {index: {"b": base, "e": exponent, "r": result}} from the model"""
    values: dict[int, dict[str, int]] = {}
    for match in exp_arg_pattern.finditer(solver_stdout):
        kind, index = match.group(1), int(match.group(2))
        values.setdefault(index, {})[kind] = parse_const_value(match.group(3))
    return values


def bv256(value: int) -> str:
    return f"(_ bv{value % WORD_MODULUS} 256)"


def exp_table(base: int, exponent: str, otherwise: str) -> str:
    """
    `base ** exponent` for a constant base, as a nested ite over the exponents below 256.

    For an even base, the table is exact: b ** e == 0 mod 2**256 for e >= 256. For an odd
    base, larger exponents fall back to `otherwise`.
    """
    if base % WORD_MODULUS == 1:
        return bv256(1)

    entries = []
    value = 1
    for _ in range(256):
        entries.append(value)
        value = value * base % WORD_MODULUS

    if base % 2 == 0:
        while entries and entries[-1] == 0:
            entries.pop()
        result = bv256(0)
    else:
        result = otherwise

    for k in reversed(range(len(entries))):
        result = f"(ite (= {exponent} {bv256(k)}) {bv256(entries[k])} {result})"
    return result


def exp_square_and_multiply(i: int, exponent: int) -> str:
    """`pcex_expr_i == pcex_expb_i ** exponent`, with O(log exponent) multiplications"""
    b, _, r = exp_names(i)

    if exponent == 0:
        return f"(assert (= {r} {bv256(1)}))\n"

    lines = []
    square, acc, bit = b, None, 0
    while True:
        if (exponent >> bit) & 1:
            if acc is None:
                acc = square
            else:
                product = f"pcex_expm_{i}_{bit}"
                lines.append(
                    f"(declare-fun {product} () (_ BitVec 256))\n"
                    f"(assert (= {product} (bvmul {acc} {square})))\n"
                )
                acc = product
        bit += 1
        if exponent >> bit == 0:
            break
        next_square = f"pcex_exps_{i}_{bit}"
        lines.append(
            f"(declare-fun {next_square} () (_ BitVec 256))\n"
            f"(assert (= {next_square} (bvmul {square} {square})))\n"
        )
        square = next_square

    lines.append(f"(assert (= {r} {acc}))\n")
    return "".join(lines)


def exact_exp_fact(i: int, app: ExpApp) -> str:
    """Exact (or partial, for an odd constant base) definition of the i-th application"""
    _, e, r = exp_names(i)
    if app.base_value is not None:
        return f"(assert (= {r} {exp_table(app.base_value, e, r)}))\n"
    if app.exponent_value is not None and app.exponent_value < MAX_EXPANDED_EXPONENT:
        return exp_square_and_multiply(i, app.exponent_value)
    return ""


def exp_point_fact(base: int, exponent: int) -> str:
    result = pow(base, exponent, WORD_MODULUS)
    return (
        f"(assert (= ({EXP_NAME} {bv256(base)} {bv256(exponent)}) {bv256(result)}))\n"
    )


def short_int(value: int) -> str:
    return str(value) if value < 10**20 else hex(value)


def exp_invalid_reason(
    apps: ExpApps, values: dict, disagree: list[int], missing: list[int]
) -> str:
    details = []
    advice = set()
    for i in (missing + disagree)[:2]:
        app = apps.apps[i]
        what = app.describe()
        if app.base_value is None and app.exponent_value is None:
            what += " (symbolic base and exponent)"
            advice.add(
                "constrain the operands with vm.assume (e.g. exponent < 256) "
                "or make the base or the exponent constant"
            )
        elif app.base_value is not None:
            advice.add("constrain the exponent with vm.assume (e.g. exponent < 256)")
        else:
            what += " (exponent too large to expand)"

        v = values.get(i, {})
        if {"b", "e", "r"} <= v.keys():
            b, e, r = v["b"], v["e"], v["r"]
            real = pow(b, e, WORD_MODULUS)
            details.append(
                f"{what}: the model takes {short_int(b)} ** {short_int(e)} = "
                f"{short_int(r)} instead of {short_int(real)}"
            )
        else:
            details.append(f"{what}: the solver did not report its operands")

    more = len(missing) + len(disagree) - len(details)
    if more > 0:
        details.append(f"and {more} more")

    reason = "EXP is approximated: " + "; ".join(details)
    if advice:
        reason += " (" + "; ".join(sorted(advice)) + ")"
    return reason


def solve_with_exp_refinement(ctx: PathContext) -> SolverOutput:
    """solve_end_to_end() for paths with EXP applications, with --pretty-counterexamples"""
    decls = exp_arg_decls(ctx.exp_apps)
    if ctx.sha3_args and ctx.args.keccak_refinement_rounds > 0:
        decls += sha3_arg_decls(ctx.sha3_args)

    ctx = replace(ctx, query=SMTQuery(ctx.query.smtlib + decls, ctx.query.assertions))
    return refine_exp(ctx, _solve_end_to_end(ctx))


def refine_exp(ctx: PathContext, solver_output: SolverOutput) -> SolverOutput:
    verbose = print if ctx.args.verbose >= 1 else lambda *args, **kwargs: None

    apps = ctx.exp_apps
    use_keccak = bool(ctx.sha3_args) and ctx.args.keccak_refinement_rounds > 0
    max_rounds = PCEX_EXP_REFINEMENT_ROUNDS + (
        ctx.args.keccak_refinement_rounds if use_keccak else 0
    )

    # the abstractions of multiplication and division are replaced by their definitions
    base_smtlib = refine(ctx.query).smtlib

    exact, points, keccaks = None, {}, {}
    solved_refined = False
    last_sat = None
    reasons = []

    values, disagree, missing, others = {}, [], [], []
    new_keccaks, keccak_consistent = {}, True

    for round in range(max_rounds + 1):
        result, model = solver_output.result, solver_output.model
        if result == unsat:
            return solver_output

        if result != sat or model is None:
            if last_sat is None:
                return solver_output
            # keep the last counterexample rather than dropping it: only unsat proves its absence
            verbose(f"  Refined query result: {result}")
            reasons.append(UNDECIDED_REASON)
            break

        last_sat = solver_output

        try:
            with open(f"{solver_output.query_file}.out") as f:
                stdout = f.read()
        except OSError:
            reasons.append("the solver output could not be read")
            break

        values = parse_exp_arg_values(stdout)
        disagree, missing = [], []
        for i in range(len(apps)):
            v = values.get(i, {})
            if not {"b", "e", "r"} <= v.keys():
                missing.append(i)
            elif pow(v["b"], v["e"], WORD_MODULUS) != v["r"]:
                disagree.append(i)

        others = sorted(set(abstraction_name_pattern.findall(stdout)) - {EXP_NAME})

        new_keccaks, keccak_consistent = {}, True
        if use_keccak:
            for size, value in parse_sha3_arg_values(stdout).values():
                if size % 8 or (size, value) in keccaks:
                    continue
                fact = keccak_fact(size, value)
                if fact is None:
                    keccak_consistent = False
                    continue
                new_keccaks[size, value] = fact[0]

        exp_ok = apps.complete and not disagree and not missing
        if exp_ok and not others and not new_keccaks and keccak_consistent:
            verbose("  The model agrees with the real EXP")
            return replace(
                solver_output,
                model=PotentialModel(model=model.model, is_valid=True),
            )

        if round == max_rounds or not apps.complete:
            break

        added = False
        if exact is None and (disagree or missing):
            exact = "".join(exact_exp_fact(i, app) for i, app in enumerate(apps.apps))
            added = bool(exact)

        for i in disagree:
            key = (values[i]["b"], values[i]["e"])
            if key not in points:
                points[key] = exp_point_fact(*key)
                added = True

        if new_keccaks:
            keccaks.update(new_keccaks)
            added = True

        # the first refined query also replaces the abstractions of mul/div by their definitions
        if not added and (solved_refined or not others):
            break

        verbose(
            f"  Checking again with {len(points)} EXP value(s), "
            f"{len(keccaks)} keccak value(s) (round {round + 1})"
        )
        refined_ctx = replace(
            ctx,
            query=SMTQuery(
                base_smtlib
                + (exact or "")
                + "".join(points.values())
                + "".join(keccaks.values()),
                ctx.query.assertions,
            ),
            suffix=f".pcex{round + 1}",
        )
        solver_output = solve_low_level(refined_ctx)
        solved_refined = True

        # an unsat core of the refined query may depend on the (unnamed) facts,
        # so it cannot be reused for other queries
        if solver_output.unsat_core is not None:
            solver_output = replace(solver_output, unsat_core=None)

    if not apps.complete:
        reasons.append(f"too many exponentiations to check (more than {MAX_EXP_APPS})")
    if others:
        reasons.append(f"relies on {', '.join(others)}, which is not modeled exactly")
    if disagree or missing:
        reasons.append(exp_invalid_reason(apps, values, disagree, missing))
    if use_keccak and (new_keccaks or not keccak_consistent):
        reasons.append(KECCAK_INVALID_REASON)

    reason = "; ".join(reasons) or "relies on an approximation of the EVM semantics"
    verbose(f"  Potentially invalid counterexample: {reason}")
    potential_model = PotentialModel(model=last_sat.model.model, is_valid=False)
    return replace(last_sat, model=potential_model, invalid_reason=reason)


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
