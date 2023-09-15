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
        help="run tests in the given contract only",
    )
    parser.add_argument(
        "--function",
        metavar="FUNCTION_NAME_PREFIX",
        default="check_",
        help="run tests matching the given prefix only (default: %(default)s)",
    )

    parser.add_argument(
        "--loop",
        metavar="MAX_BOUND",
        type=int,
        default=2,
        help="set loop unrolling bounds (default: %(default)s)",
    )
    parser.add_argument(
        "--width", metavar="MAX_WIDTH", type=int, help="set the max number of paths"
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
        help="use uninterpreted abstractions for unknown external calls with the given function signatures (default: %(default)s)",
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
        "--error-unknown",
        action="store_true",
        help="turn unknown counterexample warnings to errors",
    )

    # build options
    group_build = parser.add_argument_group("Build options")

    group_build.add_argument(
        "--forge-build-out",
        metavar="DIRECTORY_NAME",
        default="out",
        help="forge build artifacts directory name (default: %(default)s)",
    )

    # smt solver options
    group_solver = parser.add_argument_group("Solver options")

    group_solver.add_argument(
        "--no-smt-add", action="store_true", help="do not interpret `+`"
    )
    group_solver.add_argument(
        "--no-smt-sub", action="store_true", help="do not interpret `-`"
    )
    group_solver.add_argument(
        "--no-smt-mul", action="store_true", help="do not interpret `*`"
    )
    group_solver.add_argument("--smt-div", action="store_true", help="interpret `/`")
    group_solver.add_argument("--smt-mod", action="store_true", help="interpret `mod`")
    group_solver.add_argument(
        "--smt-div-by-const", action="store_true", help="interpret division by constant"
    )
    group_solver.add_argument(
        "--smt-mod-by-const", action="store_true", help="interpret constant modulo"
    )
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
        "--solver-fresh",
        action="store_true",
        help="run an extra solver with a fresh state for unknown",
    )
    group_solver.add_argument(
        "--solver-subprocess",
        action="store_true",
        help="run an extra solver in subprocess for unknown",
    )
    group_solver.add_argument(
        "--solver-parallel",
        action="store_true",
        help="run assertion solvers in parallel",
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
    group_experimental.add_argument(
        "--print-potential-counterexample",
        action="store_true",
        help="print potentially invalid counterexamples",
    )

    return parser
