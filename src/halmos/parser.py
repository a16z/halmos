# SPDX-License-Identifier: AGPL-3.0

import configargparse
import os

from typing import List, Optional

# type hint for the argument parser
ArgParser = configargparse.ArgParser

# type hint for the arguments
Args = configargparse.Namespace


def _mk_root_parser() -> ArgParser:
    root_parser = configargparse.ArgumentParser()
    root_parser.add_argument(
        "--root",
        metavar="DIRECTORY",
        default=os.getcwd(),
    )

    return root_parser


def _mk_arg_parser(config_file_provider: "ConfigFileProvider") -> ArgParser:
    parser = configargparse.ArgParser(
        prog="halmos",
        epilog="For more information, see https://github.com/a16z/halmos",
        default_config_files=config_file_provider.provide(),
        config_file_parser_class=configargparse.TomlConfigParser(sections=["global"]),
        add_config_file_help=True,
        args_for_setting_config_path=["--config"],
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
        help="run tests in the given contract. Shortcut for `--match-contract '^{NAME}$'`.",
    )
    parser.add_argument(
        "--match-contract",
        "--mc",
        metavar="CONTRACT_NAME_REGEX",
        default="",
        help="run tests in contracts matching the given regex. Ignored if the --contract name is given. (default: '%(default)s')",
    )
    parser.add_argument(
        "--function",
        metavar="FUNCTION_NAME_PREFIX",
        default="check_",
        help="run tests matching the given prefix. Shortcut for `--match-test '^{PREFIX}'`. (default: '%(default)s')",
    )
    parser.add_argument(
        "--match-test",
        "--mt",
        metavar="FUNCTION_NAME_REGEX",
        default="",
        help="run tests matching the given regex. The --function prefix is automatically added, unless the regex starts with '^'. (default: '%(default)s')",
    )

    parser.add_argument(
        "--loop",
        metavar="MAX_BOUND",
        type=int,
        default=2,
        help="set loop unrolling bounds (default: %(default)s)",
    )
    parser.add_argument(
        "--width",
        metavar="MAX_WIDTH",
        type=int,
        default=2**64,
        help="set the max number of paths (default: %(default)s)",
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
        "--uninterpreted-unknown-calls",
        metavar="SELECTOR1,SELECTOR2,...",
        # IERC721.onERC721Received, IERC1271.isValidSignature, IERC1155.onERC1155Received, IERC1155.onERC1155BatchReceived
        default="0x150b7a02,0x1626ba7e,0xf23a6e61,0xbc197c81",
        help="use uninterpreted abstractions for unknown external calls with the given function signatures (default: '%(default)s')",
    )
    parser.add_argument(
        "--return-size-of-unknown-calls",
        metavar="BYTE_SIZE",
        type=int,
        default=32,
        help="set the byte size of return data from uninterpreted unknown external calls (default: %(default)s)",
    )

    parser.add_argument(
        "--storage-layout",
        choices=["solidity", "generic"],
        default="solidity",
        help="Select one of the available storage layout models. The generic model should only be necessary for vyper, huff, or unconventional storage patterns in yul.",
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
        "--no-test-constructor",
        action="store_true",
        help="do not run the constructor of test contracts",
    )

    parser.add_argument(
        "--ffi",
        action="store_true",
        help="allow the usage of FFI to call external functions",
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
        "--json-output", metavar="JSON_FILE_PATH", help="output test results in JSON"
    )
    group_debug.add_argument(
        "--minimal-json-output",
        action="store_true",
        help="include minimal information in the JSON output",
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
    group_debug.add_argument(
        "--early-exit",
        action="store_true",
        help="stop after a counterexample is found",
    )

    group_debug.add_argument(
        "--dump-smt-queries",
        action="store_true",
        help="dump SMT queries for assertion violations",
    )

    # build options
    group_build = parser.add_argument_group("Build options")

    group_build.add_argument(
        "--forge-build-out",
        metavar="DIRECTORY_NAME",
        default="out",
        help="forge build artifacts directory name (default: '%(default)s')",
    )

    # smt solver options
    group_solver = parser.add_argument_group("Solver options")

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
        help="set timeout (in milliseconds) for solving branching conditions; 0 means no timeout (default: %(default)s)",
    )
    group_solver.add_argument(
        "--solver-timeout-assertion",
        metavar="TIMEOUT",
        type=int,
        default=1000,
        help="set timeout (in milliseconds) for solving assertion violation conditions; 0 means no timeout (default: %(default)s)",
    )
    group_solver.add_argument(
        "--solver-max-memory",
        metavar="SIZE",
        type=int,
        default=0,
        help="set memory limit (in megabytes) for the solver; 0 means no limit (default: %(default)s)",
    )
    group_solver.add_argument(
        "--solver-command",
        metavar="COMMAND",
        help="use the given command when invoking the solver, e.g. `z3 -model`",
    )
    group_solver.add_argument(
        "--solver-parallel",
        action="store_true",
        help="run assertion solvers in parallel",
    )
    group_solver.add_argument(
        "--solver-threads",
        metavar="N",
        type=int,
        # the default value of max_workers for ThreadPoolExecutor
        # TODO: set default value := total physical memory size / average z3 memory footprint
        default=min(32, os.cpu_count() + 4),
        help=f"set the number of threads for parallel solvers (default: %(default)s)",
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

    return parser


class ConfigFileProvider:
    def __init__(self, config_files: Optional[List[str]] = None):
        self.root_parser = _mk_root_parser()
        self.config_files = config_files

        # for testing purposes
        self.config_file_contents = None

    def resolve_config_files(self, args: str) -> List[str]:
        if self.config_files:
            return self.config_files

        # first, parse find the project root directory (containing foundry.toml)
        root_args = self.root_parser.parse_known_args(args, ignore_help_args=True)[0]

        # we expect to find halmos.toml in the project root directory
        self.config_files = [os.path.join(root_args.root, "halmos.toml")]
        return self.config_files

    def provide(self) -> Optional[List[str]]:
        return self.config_files


class ConfigParser:
    def __init__(self, config_file_provider: ConfigFileProvider = None):
        self.config_file_provider = config_file_provider or ConfigFileProvider()

        # initialized in parse_config
        self.arg_parser = None

    def parse_config(self, args: str) -> "Config":
        """
        Parse the configuration file and command line arguments.

        Resolves the configuration file path based on the --root argument.
        """
        self.config_file_provider.resolve_config_files(args)

        # construct an argument parser that can parse the configuration file
        self.arg_parser = _mk_arg_parser(self.config_file_provider)

        # parse the configuration file + command line arguments
        config_file_contents = self.config_file_provider.config_file_contents

        namespace = self.arg_parser.parse_args(
            args, config_file_contents=config_file_contents
        )
        return Config(parser=self, args=namespace)

    def parse_args(self, args: str, base_config: Optional["Config"] = None) -> "Config":
        """
        Parse command line arguments, potentially extending an existing configuration.
        """
        base_namespace = configargparse.Namespace()
        new_namespace = self.arg_parser.parse_args(args, namespace=base_namespace)

        if base_config.debug:
            self.format_values()

        return Config(parser=self, args=new_namespace, parent=base_config)

    def format_values(self):
        return self.arg_parser.format_values()


class Config:
    """
    A wrapper around the parsed configuration with some extras:

    - keeps a reference to its parser
    - can extend itself with more options
    - can format the values for debugging (shows provenance of each value)
    - can access the values of the underlying namespace as attributes
    - keeps track of its parent configuration, avoiding copies

    Not to be instantiated directly, use ConfigParser.parse_config instead.
    """

    def __init__(
        self, parser: ConfigParser = None, args: Args = None, parent: "Config" = None
    ):
        self.parser = parser
        self.args = args
        self.parent = parent

    def extend(self, more_opts: str) -> "Config":
        if more_opts:
            new_config = self.parser.parse_args(more_opts, base_config=self)
            return new_config
        else:
            return self

    def format_values(self):
        return self.parser.format_values()

    def __getattr__(self, name):
        if not hasattr(self.args, name):
            if self.parent:
                return getattr(self.parent, name)

        return getattr(self.args, name)

    def __repr__(self) -> str:
        return repr(self.args)

    def __str__(self) -> str:
        return str(self.args)
