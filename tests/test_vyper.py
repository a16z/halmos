import json

import pytest

from dolmos.__main__ import is_invalid_opcode_found, load_config, with_vyper_defaults
from dolmos.build import (
    VYPER_VERSION_PREFIX,
    build_out_view,
    build_output_iterator,
    get_source_path,
    has_vyper_contracts,
    load_forge_cache,
    normalize_vyper_artifact,
    parse_build_out,
    parse_devdoc,
    parse_natspec,
    parse_vyper_docstrings,
)
from dolmos.bytevec import ByteVec
from dolmos.config import ConfigSource
from dolmos.exceptions import InvalidOpcode, Revert

VYPER_SOURCE = '''# pragma version ~=0.4.3
"""
@title Test
@custom:dolmos --loop 4
"""

counter: uint256


@external
def check_one(x: uint256):
    """
    @notice first
    @custom:halmos --default-bytes-lengths 0,10
    """
    assert x != 1, UNREACHABLE


@external
def check_multiline(
    x: uint256,
    y: DynArray[uint256, 3],
) -> uint256:  # trailing comment
    \'\'\'
    @custom:dolmos --loop 5
    \'\'\'
    return x


@external
def no_doc(x: uint256):
    pass
'''

ABI = [
    {
        "type": "function",
        "name": "check_one",
        "inputs": [{"name": "x", "type": "uint256"}],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "check_multiline",
        "inputs": [
            {"name": "x", "type": "uint256"},
            {"name": "y", "type": "uint256[]"},
        ],
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "no_doc",
        "inputs": [{"name": "x", "type": "uint256"}],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
]


def forge_vyper_artifact():
    # the shape of the artifacts emitted by forge for vyper
    return {
        "abi": ABI,
        "bytecode": {"object": "0x6000"},
        "deployedBytecode": {"object": "0x5f5ffd"},
        "methodIdentifiers": {},
        "id": 1,
    }


def test_parse_vyper_docstrings():
    module_doc, function_docs = parse_vyper_docstrings(VYPER_SOURCE)

    assert parse_natspec({"text": module_doc}) == "--loop 4"
    assert set(function_docs) == {"check_one", "check_multiline"}
    assert (
        parse_natspec({"text": function_docs["check_one"]})
        == "--default-bytes-lengths 0,10"
    )
    assert parse_natspec({"text": function_docs["check_multiline"]}) == "--loop 5"


def test_parse_vyper_docstrings_none():
    assert parse_vyper_docstrings("x: uint256\n") == (None, {})


@pytest.fixture
def vyper_project(tmp_path):
    (tmp_path / "test").mkdir()
    (tmp_path / "test" / "Foo.vy").write_text(VYPER_SOURCE)

    out = tmp_path / "out"
    (out / "Foo.vy").mkdir(parents=True)
    (out / "Foo.vy" / "Foo.json").write_text(json.dumps(forge_vyper_artifact()))

    (tmp_path / "cache").mkdir()
    cache = {
        "files": {
            "test/Foo.vy": {
                "sourceName": "test/Foo.vy",
                "artifacts": {
                    "Foo": {
                        "0.4.3": {
                            "default": {
                                "path": "Foo.vy/Foo.json",
                                "build_id": "x",
                            }
                        }
                    }
                },
            }
        }
    }
    (tmp_path / "cache" / "solidity-files-cache.json").write_text(json.dumps(cache))
    return tmp_path


def test_load_forge_cache(vyper_project):
    cache = load_forge_cache(str(vyper_project), str(vyper_project / "out"))
    assert cache == {"Foo.vy/Foo.json": ("test/Foo.vy", "0.4.3")}


def test_load_forge_cache_missing(tmp_path):
    assert load_forge_cache(str(tmp_path), str(tmp_path / "out")) == {}


def test_normalize_vyper_artifact(vyper_project):
    json_out = forge_vyper_artifact()
    contract_type, version, natspec = normalize_vyper_artifact(
        json_out, "Foo.vy", str(vyper_project), ("test/Foo.vy", "0.4.3")
    )

    assert contract_type == "contract"
    assert version == VYPER_VERSION_PREFIX + "0.4.3"
    assert parse_natspec(natspec) == "--loop 4"

    assert set(json_out["methodIdentifiers"]) == {
        "check_one(uint256)",
        "check_multiline(uint256,uint256[])",
        "no_doc(uint256)",
    }
    assert json_out["methodIdentifiers"]["check_one(uint256)"] == "48ad1bf6"
    assert get_source_path(json_out) == "test/Foo.vy"
    assert json_out["bytecode"]["linkReferences"] == {}
    assert json_out["metadata"]["compiler"]["version"] == "0.4.3"

    assert (
        parse_devdoc("check_one(uint256)", json_out) == "--default-bytes-lengths 0,10"
    )
    assert parse_devdoc("check_multiline(uint256,uint256[])", json_out) == "--loop 5"
    assert parse_devdoc("no_doc(uint256)", json_out) is None


def test_normalize_vyper_selector():
    # keccak256("transfer(address,uint256)")[:4]
    json_out = {
        "abi": [
            {
                "type": "function",
                "name": "transfer",
                "inputs": [
                    {"name": "to", "type": "address"},
                    {"name": "amount", "type": "uint256"},
                ],
                "outputs": [{"name": "", "type": "bool"}],
                "stateMutability": "nonpayable",
            },
            {"type": "event", "name": "Transfer", "inputs": [], "anonymous": False},
        ],
        "bytecode": {"object": "0x"},
        "deployedBytecode": {"object": "0x"},
    }
    normalize_vyper_artifact(json_out, "Token.vy", "/nonexistent", None)
    assert json_out["methodIdentifiers"] == {"transfer(address,uint256)": "a9059cbb"}


def test_normalize_vyper_interface_and_no_cache():
    json_out = {"abi": [], "bytecode": {"object": "0x"}, "deployedBytecode": {}}
    contract_type, version, natspec = normalize_vyper_artifact(
        json_out, "IFoo.vyi", "/nonexistent", None
    )
    assert contract_type == "interface"
    assert version == VYPER_VERSION_PREFIX + "unknown"
    assert natspec is None
    assert get_source_path(json_out) == "IFoo.vyi"
    assert json_out["deployedBytecode"]["object"] == "0x"


def test_parse_build_out_vyper(vyper_project):
    args = load_config(["--root", str(vyper_project)])
    build_out = parse_build_out(args)

    assert list(build_out) == [VYPER_VERSION_PREFIX + "0.4.3"]
    assert has_vyper_contracts(build_out)

    [(view, filename, contract_name)] = list(build_output_iterator(build_out))
    assert (filename, contract_name) == ("Foo.vy", "Foo")

    json_out, contract_type, natspec = view[filename][contract_name]
    assert contract_type == "contract"
    assert "check_one(uint256)" in json_out["methodIdentifiers"]
    assert parse_natspec(natspec) == "--loop 4"


def test_build_out_view():
    sol = {"A.sol": {"A": None}}
    vy1 = {"B.vy": {"B": None}}
    vy2 = {"C.vy": {"C": None}}
    build_out = {
        "0.8.30": sol,
        VYPER_VERSION_PREFIX + "0.4.3": vy1,
        VYPER_VERSION_PREFIX + "0.3.10": vy2,
    }

    assert set(build_out_view(build_out, "0.8.30")) == {"A.sol", "B.vy", "C.vy"}
    assert set(build_out_view(build_out, VYPER_VERSION_PREFIX + "0.4.3")) == {
        "A.sol",
        "B.vy",
        "C.vy",
    }

    # solidity is not shared with vyper groups if the solc version is ambiguous
    build_out["0.7.6"] = {"D.sol": {"D": None}}
    assert set(build_out_view(build_out, VYPER_VERSION_PREFIX + "0.4.3")) == {
        "B.vy",
        "C.vy",
    }

    # no vyper: unchanged, same object
    assert build_out_view({"0.8.30": sol}, "0.8.30") is sol

    # every contract is iterated exactly once
    iterated = [(f, c) for _, f, c in build_output_iterator(build_out)]
    assert sorted(iterated) == [
        ("A.sol", "A"),
        ("B.vy", "B"),
        ("C.vy", "C"),
        ("D.sol", "D"),
    ]


def test_with_vyper_defaults():
    args = with_vyper_defaults(load_config([]))
    assert args.storage_layout == "generic"
    assert args.invalid_as_failure

    # explicit settings win
    args = with_vyper_defaults(load_config(["--storage-layout", "solidity"]))
    assert args.storage_layout == "solidity"
    assert args.invalid_as_failure

    # annotations applied later still win over the vyper defaults
    args = with_vyper_defaults(load_config([]))
    args = args.with_overrides(
        ConfigSource.contract_annotation, storage_layout="solidity"
    )
    assert args.storage_layout == "solidity"


def test_invalid_as_failure_default():
    assert not load_config([]).invalid_as_failure
    assert load_config(["--invalid-as-failure"]).invalid_as_failure


class FakeOutput:
    def __init__(self, error=None, data=b""):
        self.error = error
        self.data = ByteVec(data)


class FakeContext:
    def __init__(self, error=None, data=b"", subcalls=()):
        self.output = FakeOutput(error, data)
        self._subcalls = list(subcalls)

    def last_subcall(self):
        return self._subcalls[-1] if self._subcalls else None


def test_is_invalid_opcode_found():
    invalid = FakeContext(InvalidOpcode(0xFE))
    empty_revert = FakeContext(Revert())
    ok = FakeContext()

    # directly
    assert is_invalid_opcode_found(invalid)

    # bubbled up through empty reverts
    assert is_invalid_opcode_found(FakeContext(Revert(), subcalls=[invalid]))
    assert is_invalid_opcode_found(
        FakeContext(Revert(), subcalls=[FakeContext(Revert(), subcalls=[invalid])])
    )

    # not an INVALID failure
    assert not is_invalid_opcode_found(ok)
    assert not is_invalid_opcode_found(empty_revert)
    assert not is_invalid_opcode_found(FakeContext(Revert(), subcalls=[ok]))

    # the revert carries its own data, so it's not the bubbled-up INVALID failure
    assert not is_invalid_opcode_found(
        FakeContext(Revert(), data=b"\x08\xc3\x79\xa0", subcalls=[invalid])
    )

    # the INVALID failure was caught: the call succeeded
    assert not is_invalid_opcode_found(FakeContext(subcalls=[invalid]))
