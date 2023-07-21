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
            [
                "--root",
                "examples",
                "--function",
                "test",
            ],
            "tests/expected/examples.json",
        ),
    ],
)
@pytest.mark.parametrize(
    "parallel_options",
    [
        [],
        ["--test-parallel"],
        ["--solver-parallel"],
        ["--test-parallel", "--solver-parallel"],
    ],
)
def test_main(cmd, expected_path, parallel_options):
    actual = asdict(_main(["-v", "-st"] + cmd + parallel_options))
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
