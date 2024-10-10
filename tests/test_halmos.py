import dataclasses
import json

import pytest

from halmos.__main__ import _main, rendered_calldata
from halmos.bytevec import ByteVec
from halmos.sevm import con


@pytest.mark.parametrize(
    "cmd, expected_path",
    [
        (
            ["--root", "tests/regression"],
            "tests/expected/all.json",
        ),
        (
            ["--root", "tests/ffi"],
            "tests/expected/ffi.json",
        ),
        (
            ["--root", "tests/solver"],
            "tests/expected/solver.json",
        ),
        (
            ["--root", "examples/simple"],
            "tests/expected/simple.json",
        ),
        (
            ["--root", "examples/tokens/ERC20"],
            "tests/expected/erc20.json",
        ),
        (
            ["--root", "examples/tokens/ERC721"],
            "tests/expected/erc721.json",
        ),
    ],
    ids=(
        "tests/regression",
        "tests/ffi",
        "long:tests/solver",
        "long:examples/simple",
        "long:examples/tokens/ERC20",
        "long:examples/tokens/ERC721",
    ),
)
def test_main(cmd, expected_path, halmos_options):
    actual = dataclasses.asdict(_main(cmd + halmos_options.split()))
    with open(expected_path, encoding="utf8") as f:
        expected = json.load(f)
    assert expected["exitcode"] == actual["exitcode"]
    assert_eq(expected["test_results"], actual["test_results"])


@pytest.mark.parametrize(
    "cmd",
    [
        ["--root", "tests/regression", "--contract", "SetupFailTest"],
    ],
    ids=("SetupFailTest",),
)
def test_main_fail(cmd, halmos_options):
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


def test_rendered_calldata_symbolic():
    assert rendered_calldata(ByteVec([con(1, 8), con(2, 8), con(3, 8)])) == "0x010203"


def test_rendered_calldata_symbolic_singleton():
    assert rendered_calldata(ByteVec(con(0x42, 8))) == "0x42"


def test_rendered_calldata_concrete():
    assert rendered_calldata(ByteVec([1, 2, 3])) == "0x010203"


def test_rendered_calldata_mixed():
    assert rendered_calldata(ByteVec([con(1, 8), 2, con(3, 8)])) == "0x010203"


def test_rendered_calldata_empty():
    assert rendered_calldata(ByteVec()) == "0x"
