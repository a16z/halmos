import json
import os

import pytest

from dolmos.build import (
    find_contract,
    import_libs,
    iter_artifact_dirs,
    parse_build_out,
    resolve_artifact_path,
)
from dolmos.config import ConfigSource, default_config


def write_artifact(out, rel_dir, name, source_path, code="0x6000", link_refs=None):
    path = os.path.join(out, *rel_dir.split("/"))
    os.makedirs(path, exist_ok=True)
    artifact = {
        "abi": [],
        "bytecode": {"object": code, "linkReferences": link_refs or {}},
        "deployedBytecode": {"object": code},
        "methodIdentifiers": {},
        "id": 0,
        "metadata": {"compiler": {"version": "0.8.30"}},
        "ast": {
            "absolutePath": source_path,
            "nodes": [
                {
                    "nodeType": "ContractDefinition",
                    "name": name,
                    "contractKind": "contract",
                }
            ],
        },
    }
    with open(os.path.join(path, f"{name}.json"), "w") as f:
        json.dump(artifact, f)


@pytest.fixture
def conflicting_out(tmp_path):
    """build output of src/A.sol and src/nested/A.sol, both defining Token (halmos#582)"""
    out = str(tmp_path / "out")
    write_artifact(out, "A.sol", "Token", "src/A.sol", code="0x6001")
    write_artifact(out, "nested/A.sol", "Token", "src/nested/A.sol", code="0x6002")
    write_artifact(out, "deeper/nested/B.sol", "Other", "src/deeper/nested/B.sol")
    os.makedirs(os.path.join(out, "build-info"))
    with open(os.path.join(out, "build-info", "abc.json"), "w") as f:
        f.write("{}")
    return out


def test_iter_artifact_dirs(conflicting_out):
    assert [rel for rel, _ in iter_artifact_dirs(conflicting_out)] == [
        "A.sol",
        "deeper/nested/B.sol",
        "nested/A.sol",
    ]


def test_parse_build_out_finds_nested_artifacts(tmp_path, conflicting_out):
    args = default_config().with_overrides(
        source=ConfigSource.command_line, root=str(tmp_path)
    )
    build_out = parse_build_out(args)
    files = build_out["0.8.30"]
    assert sorted(files) == ["A.sol", "deeper/nested/B.sol", "nested/A.sol"]
    assert files["A.sol"]["Token"][0]["ast"]["absolutePath"] == "src/A.sol"
    assert (
        files["nested/A.sol"]["Token"][0]["ast"]["absolutePath"] == "src/nested/A.sol"
    )


def test_find_contract_uses_the_source_path(tmp_path, conflicting_out):
    args = default_config().with_overrides(
        source=ConfigSource.command_line, root=str(tmp_path)
    )
    files = parse_build_out(args)["0.8.30"]

    top = find_contract(files, "src/A.sol", "Token")
    nested = find_contract(files, "src/nested/A.sol", "Token")
    assert top[0]["bytecode"]["object"] == "0x6001"
    assert nested[0]["bytecode"]["object"] == "0x6002"
    assert find_contract(files, "src/deeper/nested/B.sol", "Other") is not None
    assert find_contract(files, "src/Missing.sol", "Token") is None


def test_import_libs_from_nested_artifact(tmp_path):
    out = str(tmp_path / "out")
    placeholder = "__$" + "0" * 34 + "$__"
    link_refs = {"src/nested/Lib.sol": {"Lib": [{"start": 1, "length": 20}]}}
    write_artifact(out, "Lib.sol", "Lib", "src/Lib.sol", code="0x6011")
    write_artifact(out, "nested/Lib.sol", "Lib", "src/nested/Lib.sol", code="0x6022")
    args = default_config().with_overrides(
        source=ConfigSource.command_line, root=str(tmp_path)
    )
    files = parse_build_out(args)["0.8.30"]

    libs = import_libs(files, "0x73" + placeholder + "00", link_refs)
    assert libs["src/nested/Lib.sol:Lib"]["hexcode"] == "0x6022"
    assert libs["src/nested/Lib.sol:Lib"]["placeholder"] == placeholder


def test_resolve_artifact_path(conflicting_out):
    def rel(path):
        return os.path.relpath(path, conflicting_out).replace(os.sep, "/")

    assert rel(resolve_artifact_path(conflicting_out, "src/A.sol", "Token")) == (
        "A.sol/Token.json"
    )
    assert rel(resolve_artifact_path(conflicting_out, "src/nested/A.sol", "Token")) == (
        "nested/A.sol/Token.json"
    )
    # a path relative to the source directory is enough to disambiguate
    assert rel(resolve_artifact_path(conflicting_out, "nested/A.sol", "Token")) == (
        "nested/A.sol/Token.json"
    )
    # a unique nested artifact is found from its file name alone
    assert rel(resolve_artifact_path(conflicting_out, "B.sol", "Other")) == (
        "deeper/nested/B.sol/Other.json"
    )

    # ambiguous file name, as in foundry
    with pytest.raises(ValueError, match="multiple artifacts"):
        resolve_artifact_path(conflicting_out, "A.sol", "Token")

    with pytest.raises(FileNotFoundError):
        resolve_artifact_path(conflicting_out, "A.sol", "Missing")
