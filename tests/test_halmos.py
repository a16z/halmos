import pytest
import json

from typing import Dict
from dataclasses import asdict

from halmos.__main__ import _main


@pytest.mark.parametrize(
    "cmd, expected_path",
    [
        (
            ["--root", "tests"],
            "tests/expected/all.json",
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
        (
            ["--root", "examples/tokens/dei"],
            "tests/expected/dei.json",
        ),
    ],
    ids=(
        "tests",
        "examples/toy",
        "long:examples/tokens/ERC20",
        "long:examples/tokens/ERC721",
        "long:examples/tokens/dei",
    ),
)
@pytest.mark.parametrize(
    "parallel_options",
    [
        [],
        ["--test-parallel"],
        ["--solver-parallel"],
        ["--test-parallel", "--solver-parallel"],
    ],
    ids=(
        "sequential",
        "test-parallel",
        "solver-parallel",
        "test-parallel-solver-parallel",
    ),
)
def test_main(cmd, expected_path, parallel_options):
    common_options = ["-v", "-st", "--error-unknown"]
    actual = asdict(_main(cmd + common_options + parallel_options))
    with open(expected_path, encoding="utf8") as f:
        expected = json.load(f)
    assert expected["exitcode"] == actual["exitcode"]
    assert_eq(expected["test_results"], actual["test_results"])


def assert_eq(m1: Dict, m2: Dict) -> int:
    assert list(m1.keys()) == list(m2.keys())
    for c in m1:
        l1 = sorted(m1[c], key=lambda x: x["name"])
        l2 = sorted(m2[c], key=lambda x: x["name"])
        assert len(l1) == len(l2)
        assert all(eq_test_result(r1, r2) for r1, r2 in zip(l1, l2))


def eq_test_result(r1: Dict, r2: Dict) -> bool:
    return (
        r1["name"] == r2["name"]
        and r1["exitcode"] == r2["exitcode"]
        and r1["num_models"] == r2["num_models"]
    )
