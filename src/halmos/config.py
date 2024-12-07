import argparse
import os
import re
import sys
from collections import OrderedDict
from collections.abc import Callable, Generator
from dataclasses import MISSING, dataclass, fields
from dataclasses import field as dataclass_field
from typing import Any

import toml

from .logs import warn

# common strings
internal = "internal"

# groups
debugging, solver, build, experimental, deprecated = (
    "Debugging options",
    "Solver options",
    "Build options",
    "Experimental options",
    "Deprecated options",
)


# helper to define config fields
def arg(
    help: str,
    global_default: Any,
    metavar: str | None = None,
    group: str | None = None,
    choices: str | None = None,
    short: str | None = None,
    countable: bool = False,
    global_default_str: str | None = None,
    action: Callable = None,
):
    return dataclass_field(
        default=None,
        metadata={
            "help": help,
            "global_default": global_default,
            "metavar": metavar,
            "group": group,
            "choices": choices,
            "short": short,
            "countable": countable,
            "global_default_str": global_default_str,
            "action": action,
        },
    )


def ensure_non_empty(values: list | set | dict) -> list:
    if not values:
        raise ValueError("required a non-empty list")
    return values


def parse_csv(values: str, sep: str = ",") -> Generator[Any, None, None]:
    """Parse a CSV string and return a generator of *non-empty* values."""
    return (x for _x in values.split(sep) if (x := _x.strip()))


class ParseCSV(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        values = ParseCSV.parse(values)
        setattr(namespace, self.dest, values)

    @staticmethod
    def parse(values: str) -> list[int]:
        return ensure_non_empty([int(x) for x in parse_csv(values)])

    @staticmethod
    def unparse(values: list[int]) -> str:
        return ",".join([str(v) for v in values])


class ParseErrorCodes(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        values = ParseErrorCodes.parse(values)
        setattr(namespace, self.dest, values)

    @staticmethod
    def parse(values: str) -> set[int]:
        values = values.strip()
        # return empty set, which will be interpreted as matching any value in Exec.reverted_with_panic()
        if values == "*":
            return set()

        # support multiple bases: decimal, hex, etc.
        return ensure_non_empty(set(int(x, 0) for x in parse_csv(values)))

    @staticmethod
    def unparse(values: set[int]) -> str:
        if not values:
            return "*"
        return ",".join([f"0x{v:02x}" for v in values])


class ParseArrayLengths(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        values = ParseArrayLengths.parse(values)
        setattr(namespace, self.dest, values)

    @staticmethod
    def parse(values: str | None) -> dict[str, list[int]]:
        if not values:
            return {}

        # syntax: --array-lengths name1=sizes1,name2=sizes2,...
        # where sizes is either a comma-separated list of integers enclosed in curly braces, or a single integer

        # remove all white spaces to simplify the pattern matching
        values = "".join(values.split())

        # check if the format is correct
        # note that the findall pattern below is not sufficient for this check
        if not re.match(r"^([^=,\{\}]+=(\{[\d,]+\}|\d+)(,|$))*$", values):
            raise ValueError(f"invalid array lengths format: {values}")

        matches = re.findall(r"([^=,\{\}]+)=(?:\{([\d,]+)\}|(\d+))", values)
        return {
            name.strip(): ensure_non_empty(
                [int(x) for x in parse_csv(sizes_lst or single_size)]
            )
            for name, sizes_lst, single_size in matches
        }

    @staticmethod
    def unparse(values: dict[str, list[int]]) -> str:
        return ",".join(
            [f"{k}={{{','.join([str(v) for v in vs])}}}" for k, vs in values.items()]
        )


# TODO: add kw_only=True when we support Python>=3.10
@dataclass(frozen=True)
class Config:
    """Configuration object for halmos.

    Don't instantiate this directly, since all fields have default value None. Instead, use:

     - `default_config()` to get the default configuration with the actual default values
     - `with_overrides()` to create a new configuration object with some fields overridden
    """

    ### Internal fields (not used to generate arg parsers)

    _parent: "Config" = dataclass_field(
        repr=False,
        metadata={
            internal: True,
        },
    )

    _source: str = dataclass_field(
        metadata={
            internal: True,
        },
    )

    ### General options
    #
    # These are the fields that will be used to generate arg parsers
    # We don't want them to have an actual default value, new Config() objects
    # should only have None values for these fields.
    #
    # Constructing a Config object with the actual default values is the responsibility
    # of the `default_config()` function, and it uses the `global_default` metadata field
    # for that.
    #
    # The reason for this is that when you construct a Config object from some external
    # arguments, we only want the external arguments to be set, and not the default values.
    #
    # We can then layer these Config objects on top of the `default_config()`

    root: str = arg(
        help="project root directory",
        metavar="ROOT",
        global_default=os.getcwd,
        global_default_str="current working directory",
    )

    config: str = arg(
        help="path to the config file",
        metavar="FILE",
        global_default=lambda: os.path.join(os.getcwd(), "halmos.toml"),
        global_default_str="ROOT/halmos.toml",
    )

    contract: str = arg(
        help="run tests in the given contract. Shortcut for `--match-contract '^{NAME}$'`.",
        global_default="",
        metavar="CONTRACT_NAME",
    )

    match_contract: str = arg(
        help="run tests in contracts matching the given regex. Ignored if the --contract name is given.",
        global_default="",
        metavar="CONTRACT_NAME_REGEX",
        short="mc",
    )

    function: str = arg(
        help="run tests matching the given prefix. Shortcut for `--match-test '^{PREFIX}'`.",
        global_default="check_",
        metavar="FUNCTION_NAME_PREFIX",
    )

    match_test: str = arg(
        help="run tests matching the given regex. The --function prefix is automatically added, unless the regex starts with '^'.",
        global_default="",
        metavar="FUNCTION_NAME_REGEX",
        short="mt",
    )

    panic_error_codes: str = arg(
        help="specify Panic error codes to be treated as test failures; use '*' to include all error codes",
        global_default="0x01",
        metavar="ERROR_CODE1,ERROR_CODE2,...",
        action=ParseErrorCodes,
    )

    loop: int = arg(
        help="set loop unrolling bounds",
        global_default=2,
        metavar="MAX_BOUND",
    )

    width: int = arg(
        help="set the max number of paths; 0 means unlimited",
        global_default=0,
        metavar="MAX_WIDTH",
    )

    depth: int = arg(
        help="set the maximum length in steps of a single path; 0 means unlimited",
        global_default=0,
        metavar="MAX_DEPTH",
    )

    array_lengths: str = arg(
        help="specify lengths for dynamic-sized arrays, bytes, and string types. Lengths can be specified as a comma-separated list of integers enclosed in curly braces, or as a single integer.",
        global_default=None,
        metavar="NAME1={LENGTH1,LENGTH2,...},NAME2=LENGTH3,...",
        action=ParseArrayLengths,
    )

    default_array_lengths: str = arg(
        help="set default lengths for dynamic-sized arrays (excluding bytes and string) not specified in --array-lengths",
        global_default="0,1,2",
        metavar="LENGTH1,LENGTH2,...",
        action=ParseCSV,
    )

    default_bytes_lengths: str = arg(
        help="set default lengths for bytes and string types not specified in --array-lengths",
        global_default="0,65,1024",  # 65 is ECDSA signature size
        metavar="LENGTH1,LENGTH2,...",
        action=ParseCSV,
    )

    storage_layout: str = arg(
        help="Select one of the available storage layout models. The generic model should only be necessary for vyper, huff, or unconventional storage patterns in yul.",
        global_default="solidity",
        choices=["solidity", "generic"],
    )

    ffi: bool = arg(
        help="allow the usage of FFI to call external functions",
        global_default=False,
    )

    version: bool = arg(
        help="print the version number",
        global_default=False,
    )

    ### Debugging options

    verbose: int = arg(
        help="increase verbosity levels: -v, -vv, -vvv, ...",
        global_default=0,
        group=debugging,
        short="v",
        countable=True,
    )

    statistics: bool = arg(
        help="print statistics",
        global_default=False,
        group=debugging,
        short="st",
    )

    no_status: bool = arg(
        help="disable progress display",
        global_default=False,
        group=debugging,
    )

    debug: bool = arg(
        help="run in debug mode",
        global_default=False,
        group=debugging,
    )

    log: str = arg(
        help="log every execution steps in JSON",
        global_default=None,
        metavar="LOG_FILE_PATH",
        group=debugging,
    )

    json_output: str = arg(
        help="output test results in JSON",
        global_default=None,
        metavar="JSON_FILE_PATH",
        group=debugging,
    )

    minimal_json_output: bool = arg(
        help="include minimal information in the JSON output",
        global_default=False,
        group=debugging,
    )

    print_steps: bool = arg(
        help="print every execution step",
        global_default=False,
        group=debugging,
    )

    print_mem: bool = arg(
        help="when --print-steps is enabled, also print memory contents",
        global_default=False,
        group=debugging,
    )

    print_states: bool = arg(
        help="print all final execution states",
        global_default=False,
        group=debugging,
    )

    print_success_states: bool = arg(
        help="print successful execution states",
        global_default=False,
        group=debugging,
    )

    print_failed_states: bool = arg(
        help="print failed execution states",
        global_default=False,
        group=debugging,
    )

    print_blocked_states: bool = arg(
        help="print blocked execution states",
        global_default=False,
        group=debugging,
    )

    print_setup_states: bool = arg(
        help="print setup execution states",
        global_default=False,
        group=debugging,
    )

    print_full_model: bool = arg(
        help="print full counterexample model",
        global_default=False,
        group=debugging,
    )

    early_exit: bool = arg(
        help="stop after a counterexample is found",
        global_default=False,
        group=debugging,
    )

    dump_smt_queries: bool = arg(
        help="dump SMT queries for assertion violations",
        global_default=False,
        group=debugging,
    )

    disable_gc: bool = arg(
        help="disable Python's automatic garbage collection for cyclic objects. This does not affect reference counting based garbage collection.",
        global_default=False,
        group=debugging,
    )

    ### Build options

    forge_build_out: str = arg(
        help="forge build artifacts directory name",
        metavar="DIRECTORY_NAME",
        global_default="out",
        group=build,
    )

    ### Solver options

    smt_exp_by_const: int = arg(
        help="interpret constant power up to N",
        global_default=2,
        metavar="N",
        group=solver,
    )

    solver_timeout_branching: int = arg(
        help="set timeout (in milliseconds) for solving branching conditions; 0 means no timeout",
        global_default=1,
        metavar="TIMEOUT",
        group=solver,
    )

    solver_timeout_assertion: int = arg(
        help="set timeout (in milliseconds) for solving assertion violation conditions; 0 means no timeout",
        global_default=60_000,
        metavar="TIMEOUT",
        group=solver,
    )

    solver_max_memory: int = arg(
        help="set memory limit (in megabytes) for the solver; 0 means no limit",
        global_default=0,
        metavar="SIZE",
        group=solver,
    )

    solver_command: str = arg(
        help="use the given command when invoking the solver",
        global_default=None,
        metavar="COMMAND",
        group=solver,
    )

    solver_threads: int = arg(
        help="set the number of threads for parallel solvers",
        metavar="N",
        group=solver,
        global_default=(lambda: os.cpu_count() or 1),
        global_default_str="number of CPUs",
    )

    cache_solver: bool = arg(
        help="cache unsat queries using unsat cores", global_default=False, group=solver
    )

    ### Experimental options

    symbolic_jump: bool = arg(
        help="support symbolic jump destination",
        global_default=False,
        group=experimental,
    )

    ### Deprecated

    test_parallel: bool = arg(
        help="(Deprecated; no-op) run tests in parallel",
        global_default=False,
        group=deprecated,
    )

    solver_parallel: bool = arg(
        help="(Deprecated; no-op; use --solver-threads instead) run assertion solvers in parallel",
        global_default=False,
        group=deprecated,
    )

    # default set of selectors:
    # - IERC721.onERC721Received
    # - IERC1271.isValidSignature
    # - IERC1155.onERC1155Received
    # - IERC1155.onERC1155BatchReceived
    uninterpreted_unknown_calls: str = arg(
        help="(Deprecated; no-op) use uninterpreted abstractions for unknown external calls with the given function signatures",
        global_default="0x150b7a02,0x1626ba7e,0xf23a6e61,0xbc197c81",
        metavar="SELECTOR1,SELECTOR2,...",
        group=deprecated,
    )

    return_size_of_unknown_calls: int = arg(
        help="(Deprecated; no-op) set the byte size of return data from uninterpreted unknown external calls",
        global_default=32,
        metavar="BYTE_SIZE",
        group=deprecated,
    )

    ### Methods

    def __getattribute__(self, name):
        """Look up values in parent object if they are not set in the current object.

        This is because we consider the current object to override its parent.

        Because of this, printing a Config object will show a "flattened/resolved" view of the configuration.
        """

        # look up value in current object
        value = object.__getattribute__(self, name)
        if value is not None:
            return value

        # look up value in parent object
        parent = object.__getattribute__(self, "_parent")
        if parent is not None:
            return getattr(parent, name)

        return value

    def with_overrides(self, source: str, **overrides):
        """Create a new configuration object with some fields overridden.

        Use vars(namespace) to pass in the arguments from an argparse parser or
        just a dictionary with the overrides (e.g. from a toml or json file)."""

        try:
            return Config(_parent=self, _source=source, **overrides)
        except TypeError as e:
            # follow argparse error message format and behavior
            warn(f"error: unrecognized argument: {str(e).split()[-1]}")
            sys.exit(2)

    def value_with_source(self, name: str) -> tuple[Any, str]:
        # look up value in current object
        value = object.__getattribute__(self, name)
        if value is not None:
            return (value, self._source)

        # look up value in parent object
        parent = self._parent
        if parent is not None:
            return parent.value_with_source(name)

        return (value, self._source)

    def values_with_sources(self) -> dict[str, tuple[Any, str]]:
        # field -> (value, source)
        values = {}
        for field in fields(self):
            if field.metadata.get(internal):
                continue
            values[field.name] = self.value_with_source(field.name)
        return values

    def values(self):
        skip_empty = self._parent is not None

        for field in fields(self):
            if field.metadata.get(internal):
                continue

            field_value = object.__getattribute__(self, field.name)
            if skip_empty and field_value is None:
                continue

            yield field.name, field_value

    def values_by_layer(self) -> dict[str, tuple[str, Any]]:
        # source -> {field, value}
        if self._parent is None:
            return OrderedDict([(self._source, dict(self.values()))])

        values = self._parent.values_by_layer()
        values[self._source] = dict(self.values())
        return values

    def formatted_layers(self) -> str:
        lines = []
        for layer, values in self.values_by_layer().items():
            lines.append(f"{layer}:")
            for field, value in values.items():
                lines.append(f"  {field}: {value}")
        return "\n".join(lines)


def resolve_config_files(args: list[str], include_missing: bool = False) -> list[str]:
    config_parser = argparse.ArgumentParser()
    config_parser.add_argument(
        "--root",
        metavar="DIRECTORY",
        default=os.getcwd(),
    )

    config_parser.add_argument("--config", metavar="FILE")

    # first, parse find the project root directory (containing foundry.toml)
    # beware: errors and help flags will cause a system exit
    args = config_parser.parse_known_args(args)[0]

    # if --config is passed explicitly, use that
    # no check for existence is done here, we don't want to silently ignore
    # missing config files when they are requested explicitly
    if args.config:
        return [args.config]

    # we expect to find halmos.toml in the project root directory
    default_config_path = os.path.join(args.root, "halmos.toml")
    if not include_missing and not os.path.exists(default_config_path):
        return []

    return [default_config_path]


class TomlParser:
    def __init__(self):
        pass

    def parse_file(self, toml_file_path: str) -> dict:
        with open(toml_file_path) as f:
            return self.parse_str(f.read(), source=toml_file_path)

    # exposed for easier testing
    def parse_str(self, file_contents: str, source: str = "halmos.toml") -> dict:
        parsed = toml.loads(file_contents)
        return self.parse_dict(parsed, source=source)

    # exposed for easier testing
    def parse_dict(self, parsed: dict, source: str = "halmos.toml") -> dict:
        if len(parsed) != 1:
            warn(
                f"error: expected a single `[global]` section in the toml file, "
                f"got {len(parsed)}: {', '.join(parsed.keys())}"
            )
            sys.exit(2)

        data = parsed.get("global")
        if data is None:
            for key in parsed:
                warn(
                    f"error: expected a `[global]` section in the toml file, got '{key}'"
                )
                sys.exit(2)

        # gather custom actions
        actions = {
            field.name: field.metadata["action"]
            for field in fields(Config)
            if "action" in field.metadata
        }

        result = {}
        for key, value in data.items():
            key = key.replace("-", "_")
            action = actions.get(key)
            result[key] = action.parse(value) if action else value
        return result


def _create_default_config() -> "Config":
    values = {}

    for field in fields(Config):
        # we build the default config by looking at the global_default metadata field
        default = field.metadata.get("global_default", MISSING)
        if default == MISSING:
            continue

        # retrieve the default value
        raw_value = default() if callable(default) else default

        # parse the default value, if a custom parser is provided
        action = field.metadata.get("action", None)
        values[field.name] = action.parse(raw_value) if action else raw_value

    return Config(_parent=None, _source="default", **values)


def _create_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="halmos",
        epilog="For more information, see https://github.com/a16z/halmos",
    )

    groups = {
        None: parser,
    }

    # add arguments from the Config dataclass
    for field_info in fields(Config):
        # skip internal fields
        if field_info.metadata.get(internal, False):
            continue

        long_name = f"--{field_info.name.replace('_', '-')}"
        names = [long_name]

        short_name = field_info.metadata.get("short", None)
        if short_name:
            names.append(f"-{short_name}")

        arg_help = field_info.metadata.get("help", "")
        metavar = field_info.metadata.get("metavar", None)
        group_name = field_info.metadata.get("group", None)
        if group_name not in groups:
            groups[group_name] = parser.add_argument_group(group_name)

        group = groups[group_name]

        if field_info.type is bool:
            group.add_argument(*names, help=arg_help, action="store_true", default=None)
        elif field_info.metadata.get("countable", False):
            group.add_argument(*names, help=arg_help, action="count")
        else:
            # add the default value to the help text
            default = field_info.metadata.get("global_default", None)
            if default is not None:
                default_str = field_info.metadata.get("global_default_str", None)
                default_str = repr(default) if default_str is None else default_str
                arg_help += f" (default: {default_str})"

            kwargs = {
                "help": arg_help,
                "metavar": metavar,
                "type": field_info.type,
            }
            if choices := field_info.metadata.get("choices", None):
                kwargs["choices"] = choices
            if action := field_info.metadata.get("action", None):
                kwargs["action"] = action
            group.add_argument(*names, **kwargs)

    return parser


def _create_toml_parser() -> TomlParser:
    return TomlParser()


# public singleton accessors
def default_config() -> "Config":
    return _default_config


def arg_parser() -> argparse.ArgumentParser:
    return _arg_parser


def toml_parser():
    return _toml_parser


# init module-level singletons
_arg_parser = _create_arg_parser()
_default_config = _create_default_config()
_toml_parser = _create_toml_parser()


# can generate a sample config file using:
# python -m halmos.config ARGS > halmos.toml
def main():
    def _to_toml_str(value: Any, type) -> str:
        assert value is not None
        if type is str:
            return f'"{value}"'
        if type is bool:
            return str(value).lower()
        return str(value)

    args = arg_parser().parse_args()
    config = default_config().with_overrides(source="command-line", **vars(args))

    # devs can have a little easter egg
    lines = [
        "#     ___       ___       ___       ___       ___       ___",
        "#    /\\__\\     /\\  \\     /\\__\\     /\\__\\     /\\  \\     /\\  \\",
        "#   /:/__/_   /::\\  \\   /:/  /    /::L_L_   /::\\  \\   /::\\  \\",
        "#  /::\\/\\__\\ /::\\:\\__\\ /:/__/    /:/L:\\__\\ /:/\\:\\__\\ /\\:\\:\\__\\",
        "#  \\/\\::/  / \\/\\::/  / \\:\\  \\    \\/_/:/  / \\:\\/:/  / \\:\\:\\/__/",
        "#    /:/  /    /:/  /   \\:\\__\\     /:/  /   \\::/  /   \\::/  /",
        "#    \\/__/     \\/__/     \\/__/     \\/__/     \\/__/     \\/__/",
    ]

    lines.append("\n[global]")
    current_group_name = None

    for field_info in fields(config):
        if field_info.metadata.get(internal, False):
            # skip internal fields
            continue

        name = field_info.name.replace("_", "-")
        if name in ["config", "root", "version"]:
            # skip fields that don't make sense in a config file
            continue

        group_name = field_info.metadata.get("group", None)
        if group_name == deprecated:
            # skip deprecated options
            continue

        if group_name != current_group_name:
            separator = "#" * 80
            lines.append(f"\n{separator}")
            lines.append(f"# {group_name: ^76} #")
            lines.append(separator)
            current_group_name = group_name

        arg_help = field_info.metadata.get("help", "")
        arg_help_tokens = arg_help.split(". ")  # split on sentences
        arg_help_str = "\n# ".join(arg_help_tokens)
        lines.append(f"\n# {arg_help_str}")

        (value, source) = config.value_with_source(field_info.name)
        default = field_info.metadata.get("global_default", None)

        # unparse value if action is provided
        # note: this is a workaround because not all types can be represented in toml syntax, e.g., sets.
        if action := field_info.metadata.get("action", None):
            value = action.unparse(value)

        # callable defaults mean that the default value is not a hardcoded constant
        # it depends on the context, so don't emit it in the config file unless it
        # is explicitly set by the user on the command line
        if value is None or (callable(default) and source != "command-line"):
            metavar = field_info.metadata.get("metavar", None)
            lines.append(f"# {name} = {metavar}")
        else:
            value_str = _to_toml_str(value, field_info.type)
            lines.append(f"{name} = {value_str}")

    print("\n".join(lines))


if __name__ == "__main__":
    main()
