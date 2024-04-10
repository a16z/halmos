# SPDX-License-Identifier: AGPL-3.0

import os
import argparse


def mk_arg_parser() -> argparse.ArgumentParser:
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
        # onERC721Received, IERC1271.isValidSignature
        default="0x150b7a02,0x1626ba7e",
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
