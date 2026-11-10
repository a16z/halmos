import pytest
from test_sevm import caller, mk_ex, this

from dolmos.__main__ import with_evm_version
from dolmos.config import ConfigSource, default_config
from dolmos.evm_version import (
    EVM_VERSIONS,
    LATEST_EVM_VERSION,
    evm_version_from_metadata,
    is_at_least,
    normalize_evm_version,
    unavailable_opcodes,
)
from dolmos.exceptions import DolmosException, InvalidOpcode
from dolmos.sevm import SEVM
from dolmos.utils import EVM


def mk_sevm(fun_info, evm_version: str) -> SEVM:
    args = default_config().with_overrides(
        ConfigSource.command_line, evm_version=evm_version
    )
    return SEVM(args, fun_info)


def test_versions_are_ordered():
    assert EVM_VERSIONS.index("shanghai") < EVM_VERSIONS.index("cancun")
    assert LATEST_EVM_VERSION == "osaka"
    assert is_at_least("prague", "cancun")
    assert not is_at_least("shanghai", "cancun")


@pytest.mark.parametrize(
    "name, expected",
    [
        ("cancun", "cancun"),
        ("Cancun", "cancun"),
        ("tangerinewhistle", "tangerineWhistle"),
        ("merge", "paris"),
        ("unknown", None),
    ],
)
def test_normalize(name, expected):
    assert normalize_evm_version(name) == expected


def test_unavailable_opcodes():
    assert unavailable_opcodes("osaka") == frozenset()
    assert unavailable_opcodes("prague") == {EVM.CLZ}
    assert unavailable_opcodes("shanghai") == {
        EVM.TLOAD,
        EVM.TSTORE,
        EVM.MCOPY,
        EVM.BLOBHASH,
        EVM.BLOBBASEFEE,
        EVM.CLZ,
    }
    assert EVM.PUSH0 in unavailable_opcodes("paris")
    assert EVM.PUSH0 not in unavailable_opcodes("shanghai")
    assert EVM.BASEFEE in unavailable_opcodes("berlin")
    assert EVM.CHAINID in unavailable_opcodes("petersburg")
    assert EVM.CREATE2 in unavailable_opcodes("byzantium")
    assert EVM.REVERT in unavailable_opcodes("spuriousDragon")


def test_metadata():
    assert (
        evm_version_from_metadata({"metadata": {"settings": {"evmVersion": "paris"}}})
        == "paris"
    )
    assert evm_version_from_metadata({}) is None
    assert evm_version_from_metadata({"metadata": "not a dict"}) is None


def test_with_evm_version_from_metadata():
    args = with_evm_version(
        default_config(), {"metadata": {"settings": {"evmVersion": "shanghai"}}}
    )
    assert args.evm_version == "shanghai"


def test_with_evm_version_option_wins():
    cli = default_config().with_overrides(
        ConfigSource.command_line, evm_version="cancun"
    )
    args = with_evm_version(cli, {"metadata": {"settings": {"evmVersion": "paris"}}})
    assert args.evm_version == "cancun"


def test_with_evm_version_unknown_in_metadata():
    args = with_evm_version(
        default_config(), {"metadata": {"settings": {"evmVersion": "future"}}}
    )
    assert args.evm_version == ""  # falls back to the latest fork


def test_unsupported_version_rejected(fun_info):
    with pytest.raises(DolmosException):
        mk_sevm(fun_info, "future")


@pytest.mark.parametrize(
    "hexcode, evm_version, valid",
    [
        ("5f00", "shanghai", True),  # PUSH0; STOP
        ("5f00", "paris", False),
        ("60015f5d00", "cancun", True),  # PUSH1 1; PUSH0; TSTORE; STOP
        ("60015f5d00", "shanghai", False),
        ("60011e00", "osaka", True),  # PUSH1 1; CLZ; STOP
        ("60011e00", "prague", False),
        ("4800", "london", True),  # BASEFEE; STOP
        ("4800", "berlin", False),
    ],
)
def test_opcode_availability(hexcode, evm_version, valid, fun_info, solver):
    sevm = mk_sevm(fun_info, evm_version)
    ex = mk_ex(
        bytes.fromhex(hexcode), sevm, solver, sevm.mk_storagedata(), caller, this
    )
    [out] = list(sevm.run(ex))
    error = out.context.output.error
    if valid:
        assert error is None
    else:
        assert isinstance(error, InvalidOpcode)
