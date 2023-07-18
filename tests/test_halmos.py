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
                "tests",
                "--contract",
                "CounterTest",
                "--loop",
                "4",
                "--symbolic-storage",
            ],
            "tests/expected/counter-symbolic.json",
        ),
        (
            ["--root", "tests", "--contract", "ListTest", "--symbolic-storage"],
            "tests/expected/list-symbolic.json",
        ),
        (
            ["--root", "tests", "--contract", "StorageTest", "--symbolic-storage"],
            "tests/expected/storage-symbolic.json",
        ),
        (
            [
                "--root",
                "examples",
                "--loop",
                "256",
                "--solver-fresh",
                "--function",
                "test",
            ],
            "tests/expected/examples.json",
        ),
        (
            [
                "--root",
                "tests",
                "--contract",
                "ResetTest",
                "--reset-bytecode",
                "0xaaaa0002=0x6080604052348015600f57600080fd5b506004361060285760003560e01c8063c298557814602d575b600080fd5b600260405190815260200160405180910390f3fea2646970667358221220c2880ecd3d663c2d8a036163ee7c5d65b9a7d1749e1132fd8ff89646c6621d5764736f6c63430008130033",
            ],
            "tests/expected/reset.json",
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
    assert m1.keys() == m2.keys()
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
