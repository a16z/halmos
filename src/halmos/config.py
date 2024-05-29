import argparse
import os
import toml

from dataclasses import dataclass, field, fields, MISSING
from typing import Optional

# common strings
help, metavar, group, choices, internal, global_default, short, countable = (
    "help",
    "metavar",
    "group",
    "choices",
    "internal",
    "global_default",
    "short",
    "countable",
)

# groups
debug, solver = "Debugging options", "Solver options"

# singleton default config, access with `default_config()`
_default_config: "Config" = None

# singleton arg parser, access with `arg_parser()`
_arg_parser: argparse.ArgumentParser = None

# singleton toml parser, access with `toml_parser()`
_toml_parser: "TomlParser" = None


@dataclass(kw_only=True, frozen=True)
class Config:
    """Configuration object for halmos.

    Don't instantiate this directly, since all fields have default value None. Instead, use:

     - `default_config()` to get the default configuration with the actual default values
     - `with_overrides()` to create a new configuration object with some fields overridden
    """

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
        parent = object.__getattribute__(self, "config_parent")
        if value is None and parent is not None:
            return getattr(parent, name)

        return value

    def with_overrides(self, source: str, **overrides):
        """Create a new configuration object with some fields overridden.

        Use vars(namespace) to pass in the arguments from an argparse parser or
        just a dictionary with the overrides (e.g. from a toml or json file)."""

        return Config(config_parent=self, config_source=source, **overrides)

    ### Internal fields (not used to generate arg parsers)

    config_parent: "Config" = field(
        repr=False,
        metadata={
            internal: True,
        },
    )

    config_source: str = field(
        metadata={
            internal: True,
        },
    )

    ### General options

    root: str = field(
        default=None,
        metadata={
            help: "Project root directory",
            metavar: "PATH",
            global_default: os.getcwd(),
        },
    )

    loop: int = field(
        default=None,
        metadata={
            help: "set loop unrolling bounds",
            metavar: "MAX_BOUND",
            global_default: 2,
        },
    )

    symbolic_storage: bool = field(
        default=None,
        metadata={
            help: "set default storage values to symbolic",
            global_default: False,
        },
    )

    storage_layout: str = field(
        default=None,
        metadata={
            help: "storage layout file",
            metavar: "FILE",
            choices: ["solidity", "generic"],
            global_default: "solidity",
        },
    )

    ### Debugging options

    verbose: int = field(
        default=None,
        metadata={
            help: "increase verbosity levels: -v, -vv, -vvv, ...",
            metavar: "LEVEL",
            group: debug,
            global_default: 0,
            short: "v",
            countable: True,
        },
    )

    statistics: bool = field(
        default=None,
        metadata={
            help: "print statistics",
            group: debug,
            global_default: False,
        },
    )

    json_output: str = field(
        default=None,
        metadata={
            help: "output test results in JSON",
            metavar: "JSON_FILE_PATH",
            group: debug,
            global_default: None,
        },
    )

    ### Solver options

    solver_timeout_assertion: int = field(
        default=None,
        metadata={
            help: "set timeout (in milliseconds) for solving assertion violation conditions; 0 means no timeout (default: 1000)",
            metavar: "MILLISECONDS",
            group: solver,
            global_default: 1000,
        },
    )

    solver_parallel: bool = field(
        default=None,
        metadata={
            help: "run assertion solvers in parallel",
            group: solver,
            global_default: False,
        },
    )

    solver_threads: int = field(
        default=None,
        metadata={
            help: f"number of threads to use for assertion solving",
            metavar: "N",
            group: solver,
            global_default: os.cpu_count() or 1,
        },
    )


def default_config() -> "Config":
    global _default_config
    if _default_config is None:
        values = {}

        for field in fields(Config):
            # let's skip the actual default values
            # if field.default is not MISSING:
            #     values[field.name] = field.default

            default_value = field.metadata.get(global_default, MISSING)
            if default_value != MISSING:
                values[field.name] = default_value

        _default_config = Config(config_parent=None, config_source="default", **values)

    return _default_config


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

        short_name = field_info.metadata.get(short, None)
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
        elif field_info.metadata.get(countable, False):
            group.add_argument(*names, help=arg_help, action="count")
        else:
            kwargs = {
                "help": arg_help,
                "metavar": metavar,
                "type": field_info.type,
            }
            if choices := field_info.metadata.get("choices", None):
                kwargs["choices"] = choices
            group.add_argument(*names, **kwargs)

    return parser


def arg_parser() -> argparse.ArgumentParser:
    global _arg_parser
    if _arg_parser is None:
        _arg_parser = _create_arg_parser()
    return _arg_parser


if __name__ == "__main__":
    parser = arg_parser()
    args = parser.parse_args()
    print(args)
