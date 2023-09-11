import pytest
import json

from typing import Dict
from dataclasses import asdict

from halmos.__main__ import _main

from test_fixtures import halmos_options


@pytest.mark.parametrize(
    "cmd, expected_path",
    [
        (
            ["--root", "tests"],
            "tests/expected/all.json",
        ),
        (
            ["--root", "tests", "--function", "testFFI_"],
            "tests/expected/ffi.json",
        ),
        (
            ["--root", "examples/toy", "--function", "test"],
            "tests/expected/toy.json",
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
        "tests",
        "ffi:tests",
        "examples/toy",
        "long:examples/tokens/ERC20",
        "long:examples/tokens/ERC721",
    ),
)
def test_main(cmd, expected_path, halmos_options):
    actual = asdict(_main(cmd + halmos_options.split()))
    with open(expected_path, encoding="utf8") as f:
        expected = json.load(f)
    assert expected["exitcode"] == actual["exitcode"]
    assert_eq(expected["test_results"], actual["test_results"])


@pytest.mark.parametrize(
    "cmd",
    [
        ["--root", "tests", "--contract", "SetupFailTest"],
    ],
    ids=("SetupFailTest",),
)
def test_main_fail(cmd, halmos_options):
    actual = asdict(_main(cmd + halmos_options.split()))
    assert actual["exitcode"] != 0


def assert_eq(m1: Dict, m2: Dict) -> int:
    assert list(m1.keys()) == list(m2.keys())
    for c in m1:
        l1 = sorted(m1[c], key=lambda x: x["name"])
        l2 = sorted(m2[c], key=lambda x: x["name"])
        assert len(l1) == len(l2), c
        for r1, r2 in zip(l1, l2):
            assert r1["name"] == r2["name"]
            assert r1["exitcode"] == r2["exitcode"], f"{c} {r1['name']}"
            assert r1["num_models"] == r2["num_models"], f"{c} {r1['name']}"
