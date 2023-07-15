import pytest
import json

from typing import Dict

from halmos.__main__ import main


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
    test_results_map = {}
    main(cmd + parallel_options, test_results_map)
    with open(expected_path, encoding="utf8") as f:
        expected = json.load(f)
    assert_eq(expected, test_results_map)


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
