import argparse
import os
import sys
import toml

from collections import OrderedDict
from dataclasses import dataclass, field, fields, MISSING
from typing import Any, Dict, List, Optional, Tuple, Union as UnionType

from .utils import warn

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


@dataclass(kw_only=True, frozen=True)
class Config:
    """Configuration object for halmos.

    Don't instantiate this directly, since all fields have default value None. Instead, use:

     - `default_config()` to get the default configuration with the actual default values
     - `with_overrides()` to create a new configuration object with some fields overridden
    """

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

    root: str = field(
        default=None,
        metadata={
            help: "Project root directory",
            metavar: "PATH",
            global_default: os.getcwd(),
        },
    )

    depth: int = field(
        default=None,
        metadata={
            help: "set the max path length",
            metavar: "MAX_DEPTH",
            global_default: None,
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
            help: "set timeout (in milliseconds) for solving assertion violation conditions; 0 means no timeout",
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
        parent = object.__getattribute__(self, "config_parent")
        if value is None and parent is not None:
            return getattr(parent, name)

        return value

    def with_overrides(self, source: str, **overrides):
        """Create a new configuration object with some fields overridden.

        Use vars(namespace) to pass in the arguments from an argparse parser or
        just a dictionary with the overrides (e.g. from a toml or json file)."""

        try:
            return Config(config_parent=self, config_source=source, **overrides)
        except TypeError as e:
            # follow argparse error message format and behavior
            warn(f"error: unrecognized argument: {str(e).split()[-1]}")
            sys.exit(2)

    def value_with_source(self, name: str) -> Tuple[Any, str]:
        # look up value in current object
        value = object.__getattribute__(self, name)
        if value is not None:
            return (value, self.config_source)

        # look up value in parent object
        parent = object.__getattribute__(self, "config_parent")
        if value is None and self.config_parent is not None:
            return parent.value_with_source(name)

        return (value, self.config_source)

    def values_with_sources(self) -> Dict[str, Tuple[Any, str]]:
        # field -> (value, source)
        values = {}
        for field in fields(self):
            if field.metadata.get(internal):
                continue
            values[field.name] = self.value_with_source(field.name)
        return values

    def values(self):
        skip_empty = self.config_parent is not None

        for field in fields(self):
            if field.metadata.get(internal):
                continue

            field_value = object.__getattribute__(self, field.name)
            if skip_empty and field_value is None:
                continue

            yield field.name, field_value

    def values_by_layer(self) -> Dict[str, Tuple[str, Any]]:
        # source -> {field, value}
        if self.config_parent is None:
            return OrderedDict([(self.config_source, dict(self.values()))])

        values = self.config_parent.values_by_layer()
        values[self.config_source] = dict(self.values())
        return values

    def formatted_layers(self) -> str:
        lines = []
        for layer, values in self.values_by_layer().items():
            lines.append(f"{layer}:")
            for field, value in values.items():
                lines.append(f"  {field}: {value}")
        return "\n".join(lines)


def _mk_root_parser() -> argparse.ArgumentParser:
    root_parser = argparse.ArgumentParser()
    root_parser.add_argument(
        "--root",
        metavar="DIRECTORY",
        default=os.getcwd(),
    )

    return root_parser


def resolve_config_files(args: UnionType[str, List[str]]) -> List[str]:
    root_parser = _mk_root_parser()

    # first, parse find the project root directory (containing foundry.toml)
    # beware: errors and help flags will cause a system exit
    root_args = root_parser.parse_known_args(args)[0]

    # we expect to find halmos.toml in the project root directory
    config_files = [os.path.join(root_args.root, "halmos.toml")]
    return config_files


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
        default_value = field.metadata.get(global_default, MISSING)
        if default_value != MISSING:
            values[field.name] = default_value

    return Config(config_parent=None, config_source="default", **values)


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


if __name__ == "__main__":
    parser = arg_parser()
    args = parser.parse_args()
    config = default_config().with_overrides(source="command-line", **vars(args))
    print(config.formatted_layers())
