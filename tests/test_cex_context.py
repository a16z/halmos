"""
End-to-end tests of what counterexamples report besides the arguments of the test, and of
the selection of tests by annotations: upstream halmos issues #184, #374, #577 and #608.
"""

import re

import pytest

from dolmos.__main__ import _main
from dolmos.bytevec import ByteVec
from dolmos.contract import Contract, split_symbolic_chunks
from dolmos.zfast import BitVec, BitVecVal, Concat, ZeroExt

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")


def run(capsys, contract: str, *args):
    result = _main(["--root", "tests/regression", "--contract", contract, *args])
    out = ANSI_ESCAPE.sub("", capsys.readouterr().out)
    tests = [r for results in result.test_results.values() for r in results]
    return {r.name: r.exitcode for r in tests}, out


@pytest.mark.parametrize("layout", ["solidity", "generic"])
def test_symbolic_storage_in_counterexample(capsys, layout):
    results, out = run(capsys, "SymbolicStorageCexTest", "--storage-layout", layout)
    assert results == {
        "check_storage_cex_increment()": 1,
        "check_storage_cex_mapping()": 1,
        "check_storage_cex_scalar()": 1,
    }
    assert "Counterexample: ∅" not in out

    vault = "storage_0x00000000000000000000000000000000cccc0000"
    if layout == "solidity":
        # halmos#577: `number` must be 1 before the increment
        assert f"Counterexample: \n    {vault}_0_0_0_00 = 0x01\n" in out
        assert f"Counterexample: \n    {vault}_1_0_0_00 = 0xbeef\n" in out
        assert f"Counterexample: \n    {vault}_2_2_512_00[0x1234][0x00] = 0x4d\n" in out
    else:
        # the scalar slots are entries of a mapping from the slots: slots 0 and 1
        assert f"Counterexample: \n    {vault}_256_00[0x00] = 0x01\n" in out
        assert f"Counterexample: \n    {vault}_256_00[0x01] = 0xbeef\n" in out
        # the mapping is another one, from the key and the slot of the mapping
        assert re.search(
            rf"{re.escape(vault)}_\d+_00\[0x1234\]\[0x02\](\[0x00\])* = 0x4d\n", out
        )


def test_concrete_storage_not_in_counterexample(capsys):
    results, out = run(capsys, "ConcreteStorageCexTest")
    assert results == {"check_storage_cex_concrete(address)": 1}
    assert "storage_0x" not in out


def test_create_calldata_function_in_counterexample(capsys):
    results, out = run(capsys, "CreateCalldataCexTest")
    assert results == {"check_calldata_cex()": 1}

    # halmos#374: a function with an argument, and one without
    assert re.search(
        r"Counterexample: \n"
        r"    p_amount_uint256_[0-9a-f]+_\d+ = 0x[0-9a-f]+\n"
        r"    svm\.createCalldata: CalldataCexToken\.burn\(uint256\) \[selector 0x42966c68\]\n",
        out,
    )
    assert (
        "Counterexample: \n"
        "    svm.createCalldata: CalldataCexToken.burnAll() [selector 0x9975038c]\n"
    ) in out


@pytest.mark.parametrize(
    "contract, expected",
    [
        ("NatspecFunctionTest", {"verify_selected(uint256)": 0}),
        ("NatspecMatchTest", {"check_selected(uint256)": 0}),
    ],
)
def test_annotation_selects_tests(capsys, contract, expected):
    # halmos#184: --function and --match-test in a contract annotation
    results, _ = run(capsys, contract)
    assert results == expected


def test_command_line_overrides_annotation(capsys):
    results, _ = run(capsys, "NatspecFunctionTest", "--function", "check_")
    assert results == {"check_not_selected(uint256)": 1}


def test_jump_after_symbolic_immutable(capsys):
    # halmos#608
    results, out = run(capsys, "SymbolicImmutableTest")
    assert results == {
        "check_concrete_immutable()": 0,
        "check_jump_after_symbolic_immutable()": 0,
        "check_other_caller_reverts(address)": 0,
    }
    assert "InvalidJumpDestError" not in out


def test_split_symbolic_chunks():
    # PUSH20 <owner> CALLER EQ PUSH1 0x1d JUMPI PUSH0 PUSH0 REVERT JUMPDEST STOP
    owner = BitVec("owner", 160)
    tail = bytes.fromhex("3314601d575f5ffd5b000000")
    assert len(tail) == 12

    # the word that holds the immutable and the 12 bytes of code that follow it, as
    # written by `mstore(p, or(and(mload(p), mask), shl(96, owner)))`
    word = (ZeroExt(96, owner) << 96) | BitVecVal(int.from_bytes(tail, "big"), 256)

    code = ByteVec()
    code.append(b"\x73")
    code.append(word)

    # without the split, the bytes after the immutable are not concrete
    assert not isinstance(code.get_byte(21), int)

    split = split_symbolic_chunks(code)
    assert len(split) == len(code) == 33
    assert [split.get_byte(21 + i) for i in range(12)] == list(tail)
    assert not isinstance(split.get_byte(1), int)

    contract = Contract(code)
    assert contract.valid_jumpdests() == {29}
    assert contract.decode_instruction(21).opcode == 0x33  # CALLER

    # nothing to split: the same object
    concrete = ByteVec(b"\x5b\x00")
    assert split_symbolic_chunks(concrete) is concrete
    symbolic = ByteVec()
    symbolic.append(Concat(BitVec("x", 8), BitVec("y", 8)))
    assert len(split_symbolic_chunks(symbolic)) == 2
