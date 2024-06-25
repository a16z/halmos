import argparse
import os
import sys
import toml

from collections import OrderedDict
from dataclasses import dataclass, field, fields, MISSING
from typing import Any, Dict, List, Optional, Tuple, Union as UnionType

from .utils import warn

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
    metavar: Optional[str] = None,
    group: Optional[str] = None,
    choices: Optional[str] = None,
    short: Optional[str] = None,
    countable: bool = False,
    global_default_str: Optional[str] = None,
):
    return field(
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
        },
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

    _parent: "Config" = field(
        repr=False,
        metadata={
            internal: True,
        },
    )

    _source: str = field(
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
        help="set the length of dynamic-sized arrays including bytes and string (default: loop unrolling bound)",
        global_default=None,
        metavar="NAME1=LENGTH1,NAME2=LENGTH2,...",
    )

    # default set of selectors:
    # - IERC721.onERC721Received
    # - IERC1271.isValidSignature
    # - IERC1155.onERC1155Received
    # - IERC1155.onERC1155BatchReceived
    uninterpreted_unknown_calls: str = arg(
        help="use uninterpreted abstractions for unknown external calls with the given function signatures",
        global_default="0x150b7a02,0x1626ba7e,0xf23a6e61,0xbc197c81",
        metavar="SELECTOR1,SELECTOR2,...",
    )

    return_size_of_unknown_calls: int = arg(
        help="set the byte size of return data from uninterpreted unknown external calls",
        global_default=32,
        metavar="BYTE_SIZE",
    )

    storage_layout: str = arg(
        help="Select one of the available storage layout models. The generic model should only be necessary for vyper, huff, or unconventional storage patterns in yul.",
        global_default="solidity",
        choices=["solidity", "generic"],
    )

    symbolic_storage: bool = arg(
        help="set default storage values to symbolic",
        global_default=False,
    )

    symbolic_msg_sender: bool = arg(
        help="set msg.sender symbolic",
        global_default=False,
    )

    no_test_constructor: bool = arg(
        help="do not run the constructor of test contracts",
        global_default=False,
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
        global_default=1000,
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

    bytecode: str = arg(
        help="execute the given bytecode",
        global_default=None,
        metavar="HEX_STRING",
        group=experimental,
    )

    reset_bytecode: str = arg(
        help="reset the bytecode of given addresses after setUp()",
        global_default=None,
        metavar="ADDR1=CODE1,ADDR2=CODE2,...",
        group=experimental,
    )

    test_parallel: bool = arg(
        help="run tests in parallel", global_default=False, group=experimental
    )

    symbolic_jump: bool = arg(
        help="support symbolic jump destination",
        global_default=False,
        group=experimental,
    )

    ### Deprecated

    solver_parallel: bool = arg(
        help="(Deprecated; no-op; use --solver-threads instead) run assertion solvers in parallel",
        global_default=False,
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

    def value_with_source(self, name: str) -> Tuple[Any, str]:
        # look up value in current object
        value = object.__getattribute__(self, name)
        if value is not None:
            return (value, self._source)

        # look up value in parent object
        parent = self._parent
        if parent is not None:
            return parent.value_with_source(name)

        return (value, self._source)

    def values_with_sources(self) -> Dict[str, Tuple[Any, str]]:
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

    def values_by_layer(self) -> Dict[str, Tuple[str, Any]]:
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


def resolve_config_files(args: List[str], include_missing: bool = False) -> List[str]:
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

    def parse_file(self, toml_file_path: str) -> Dict:
        with open(toml_file_path) as f:
            return self.parse_str(f.read(), source=toml_file_path)

    # exposed for easier testing
    def parse_str(self, file_contents: str, source: str = "halmos.toml") -> Dict:
        parsed = toml.loads(file_contents)
        return self.parse_dict(parsed, source=source)

    # exposed for easier testing
    def parse_dict(self, parsed: dict, source: str = "halmos.toml") -> Dict:
        if len(parsed) != 1:
            warn(
                f"error: expected a single `[global]` section in the toml file, "
                f"got {len(parsed)}: {', '.join(parsed.keys())}"
            )
            sys.exit(2)

        data = parsed.get("global", None)
        if data is None:
            for key in parsed.keys():
                warn(
                    f"error: expected a `[global]` section in the toml file, got '{key}'"
                )
                sys.exit(2)

        return {k.replace("-", "_"): v for k, v in data.items()}


def _create_default_config() -> "Config":
    values = {}

    for field in fields(Config):
        # we build the default config by looking at the global_default metadata field
        default = field.metadata.get("global_default", MISSING)
        if default == MISSING:
            continue

        values[field.name] = default() if callable(default) else default

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

        if field_info.type == bool:
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
        if type == str:
            return f'"{value}"'
        if type == bool:
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
