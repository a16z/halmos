import argparse
import dataclasses
import json

from halmos.__main__ import _main

tests_config = {
    "tests/regression": (
        ["--root", "tests/regression"],
        "tests/expected/all.json",
    ),
    "tests/ffi": (
        ["--root", "tests/ffi"],
        "tests/expected/ffi.json",
    ),
    "tests/solver": (
        ["--root", "tests/solver"],
        "tests/expected/solver.json",
    ),
    "examples/simple": (
        ["--root", "examples/simple"],
        "tests/expected/simple.json",
    ),
    "examples/tokens/ERC20": (
        ["--root", "examples/tokens/ERC20"],
        "tests/expected/erc20.json",
    ),
    "examples/tokens/ERC721": (
        ["--root", "examples/tokens/ERC721"],
        "tests/expected/erc721.json",
    ),
}


def _test_main(cmd, expected_path, halmos_options):
    actual = dataclasses.asdict(_main(cmd + halmos_options.split()))
    with open(expected_path, encoding="utf8") as f:
        expected = json.load(f)
    assert expected["exitcode"] == actual["exitcode"]
    assert_eq(expected["test_results"], actual["test_results"])


def _test_main_fail(cmd, halmos_options):
    actual = dataclasses.asdict(_main(cmd + halmos_options.split()))
    assert actual["exitcode"] != 0


def assert_eq(m1: dict, m2: dict) -> int:
    assert list(m1.keys()) == list(m2.keys())
    for c in m1:
        l1 = sorted(m1[c], key=lambda x: x["name"])
        l2 = sorted(m2[c], key=lambda x: x["name"])
        assert len(l1) == len(l2), c
        for r1, r2 in zip(l1, l2, strict=False):
            assert r1["name"] == r2["name"]
            assert r1["exitcode"] == r2["exitcode"], f"{c} {r1['name']}"
            assert r1["num_models"] == r2["num_models"], f"{c} {r1['name']}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run halmos tests")
    parser.add_argument("test", help="Test to run")
    parser.add_argument(
        "--halmos-options", default="", help="Options to pass to halmos"
    )

    args = parser.parse_args()

    _test_main(*tests_config[args.test], args.halmos_options)

    # run extra tests
    if args.test == "tests/regression":
        _test_main_fail(
            ["--root", "tests/regression", "--contract", "SetupFailTest"],
            args.halmos_options,
        )
