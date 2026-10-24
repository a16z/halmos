# SPDX-License-Identifier: AGPL-3.0

import dataclasses
import json
from pathlib import Path

import pytest

from halmos.build import import_libs, parse_build_out
from halmos.config import default_config
from halmos.exceptions import HalmosException

COMPILER_VERSION = "0.8.26+commit.8a97fa7a"


def create_artifact(artifact_path: Path, contract_name: str, source_path: str) -> None:
    artifact_path.parent.mkdir(parents=True, exist_ok=True)
    artifact_data = {
        "ast": {
            "nodeType": "SourceUnit",
            "absolutePath": source_path,
            "id": 0,
            "nodes": [
                {
                    "nodeType": "ContractDefinition",
                    "name": contract_name,
                    "contractKind": "contract",
                    "abstract": False,
                    "documentation": None,
                }
            ],
        },
        "metadata": {"compiler": {"version": COMPILER_VERSION}},
        "bytecode": {"object": "0x60806040"},
        "deployedBytecode": {"object": "0x60806040"},
    }
    with open(artifact_path, "w", encoding="utf-8") as f:
        json.dump(artifact_data, f)


@pytest.fixture
def build_config(tmp_path: Path):
    return dataclasses.replace(
        default_config(),
        root=str(tmp_path),
        forge_build_out="out",
    )


def test_standard_artifact_path(tmp_path: Path, build_config):
    out_dir = tmp_path / "out"
    create_artifact(
        out_dir / "Counter.sol" / "Counter.json",
        "Counter",
        "src/Counter.sol",
    )

    result = parse_build_out(build_config)
    assert COMPILER_VERSION in result

    build_out_map = result[COMPILER_VERSION]
    assert "Counter.sol" in build_out_map
    contract_json, contract_type, natspec = build_out_map["Counter.sol"]["Counter"]
    assert contract_type == "contract"
    assert natspec is None
    assert contract_json["ast"]["absolutePath"] == "src/Counter.sol"


def test_alternative_and_nested_artifact_paths(tmp_path: Path, build_config):
    out_dir = tmp_path / "out"

    # Standard artifact path: out/Counter.sol/Counter.json
    create_artifact(
        out_dir / "Counter.sol" / "Counter.json",
        "Counter",
        "src/Counter.sol",
    )

    # Nested alternative artifact path from Foundry conflict resolution: out/alternative/Counter.sol/Counter.json
    create_artifact(
        out_dir / "alternative" / "Counter.sol" / "Counter.json",
        "Counter",
        "src/alternative/Counter.sol",
    )

    # Deeper nested artifact path: out/nested/sub/Token.sol/Token.json
    create_artifact(
        out_dir / "nested" / "sub" / "Token.sol" / "Token.json",
        "Token",
        "src/nested/sub/Token.sol",
    )

    # Numeric fallback suffix from Foundry conflict resolution: out/Fallback.sol_1/Fallback.json
    create_artifact(
        out_dir / "Fallback.sol_1" / "Fallback.json",
        "Fallback",
        "src/Fallback.sol",
    )

    # Non-artifact directory (build-info) with compiler input/output JSON
    build_info_dir = out_dir / "build-info"
    build_info_dir.mkdir(parents=True, exist_ok=True)
    with open(build_info_dir / "build_cache.json", "w", encoding="utf-8") as f:
        json.dump({"language": "Solidity", "sources": {}}, f)

    result = parse_build_out(build_config)
    assert COMPILER_VERSION in result

    build_out_map = result[COMPILER_VERSION]

    # Verify standard path discovery
    assert "Counter.sol" in build_out_map
    assert "Counter" in build_out_map["Counter.sol"]

    # Verify nested alternative path discovery
    assert "alternative/Counter.sol" in build_out_map
    c_json, c_type, _ = build_out_map["alternative/Counter.sol"]["Counter"]
    assert c_type == "contract"
    assert c_json["ast"]["absolutePath"] == "src/alternative/Counter.sol"

    # Verify deeper nested path discovery
    assert "nested/sub/Token.sol" in build_out_map
    assert "Token" in build_out_map["nested/sub/Token.sol"]

    # Verify numeric suffix fallback path discovery
    assert "Fallback.sol_1" in build_out_map
    assert "Fallback" in build_out_map["Fallback.sol_1"]

    # Verify non-artifact build-info directory was not parsed as a source file
    assert "build-info" not in build_out_map


def test_import_libs_with_nested_and_colliding_paths():
    # Two libraries with the same basename in different directories
    lib_a = (
        {
            "ast": {"nodeType": "SourceUnit", "absolutePath": "src/a/MyLib.sol"},
            "deployedBytecode": {"object": "0xAAAA"},
        },
        "contract",
        None,
    )
    lib_b = (
        {
            "ast": {"nodeType": "SourceUnit", "absolutePath": "src/b/MyLib.sol"},
            "deployedBytecode": {"object": "0xBBBB"},
        },
        "contract",
        None,
    )

    build_out_map = {
        "MyLib.sol": {"MyLib": lib_a},
        "b/MyLib.sol": {"MyLib": lib_b},
    }

    # Contract links against the nested library src/b/MyLib.sol
    hexcode = "0x" + "00" * 40
    link_references = {"src/b/MyLib.sol": {"MyLib": [{"start": 0, "length": 20}]}}

    libs = import_libs(build_out_map, hexcode, link_references)
    assert libs["src/b/MyLib.sol:MyLib"]["hexcode"] == "0xBBBB"


def test_import_libs_mismatched_library_raises():
    # A library with matching contract and file name exists, but its AST path belongs to a different file
    lib_a = (
        {
            "ast": {"nodeType": "SourceUnit", "absolutePath": "src/a/MyLib.sol"},
            "deployedBytecode": {"object": "0xAAAA"},
        },
        "contract",
        None,
    )

    build_out_map = {
        "MyLib.sol": {"MyLib": lib_a},
    }

    # Contract references src/other/MyLib.sol which does not exist in build_out_map
    hexcode = "0x" + "00" * 40
    link_references = {"src/other/MyLib.sol": {"MyLib": [{"start": 0, "length": 20}]}}

    # Safe behavior: must raise HalmosException rather than silently linking src/a/MyLib.sol
    with pytest.raises(HalmosException, match="not found in build output"):
        import_libs(build_out_map, hexcode, link_references)


def test_import_libs_ambiguous_library_raises():
    # Two libraries match by name without distinguishing AST metadata
    lib_1 = (
        {"deployedBytecode": {"object": "0x1111"}},
        "contract",
        None,
    )
    lib_2 = (
        {"deployedBytecode": {"object": "0x2222"}},
        "contract",
        None,
    )

    build_out_map = {
        "v1/MyLib.sol": {"MyLib": lib_1},
        "v2/MyLib.sol": {"MyLib": lib_2},
    }

    hexcode = "0x" + "00" * 40
    link_references = {"src/MyLib.sol": {"MyLib": [{"start": 0, "length": 20}]}}

    with pytest.raises(HalmosException, match="ambiguous library reference"):
        import_libs(build_out_map, hexcode, link_references)


def test_import_libs_missing_ast_path_suffix_resolution():
    # When AST metadata is missing, path suffix distinguishes between same-named libraries
    lib_tokens = (
        {"deployedBytecode": {"object": "0x1111"}},
        "contract",
        None,
    )
    lib_other = (
        {"deployedBytecode": {"object": "0x2222"}},
        "contract",
        None,
    )

    build_out_map = {
        "tokens/MyLib.sol": {"MyLib": lib_tokens},
        "other/MyLib.sol": {"MyLib": lib_other},
    }

    hexcode = "0x" + "00" * 40
    link_references = {
        "contracts/tokens/MyLib.sol": {"MyLib": [{"start": 0, "length": 20}]}
    }

    libs = import_libs(build_out_map, hexcode, link_references)
    assert libs["contracts/tokens/MyLib.sol:MyLib"]["hexcode"] == "0x1111"


def test_import_libs_numeric_suffix_resolution():
    # Foundry collision fallback suffix (.sol_1) resolves when AST is missing
    lib = (
        {"deployedBytecode": {"object": "0x3333"}},
        "contract",
        None,
    )

    build_out_map = {
        "MyLib.sol_1": {"MyLib": lib},
    }

    hexcode = "0x" + "00" * 40
    link_references = {"src/MyLib.sol": {"MyLib": [{"start": 0, "length": 20}]}}

    libs = import_libs(build_out_map, hexcode, link_references)
    assert libs["src/MyLib.sol:MyLib"]["hexcode"] == "0x3333"


def test_import_libs_legitimate_filename_with_underscore_and_digits():
    # Source file legitimately ends in underscore and digits (e.g. MyLib_1.sol)
    lib_regular = (
        {"deployedBytecode": {"object": "0x1111"}},
        "contract",
        None,
    )
    lib_collision = (
        {"deployedBytecode": {"object": "0x2222"}},
        "contract",
        None,
    )

    # 1. Standard artifact for MyLib_1.sol
    build_out_map = {
        "utils/MyLib_1.sol": {"MyLib_1": lib_regular},
    }
    hexcode = "0x" + "00" * 40
    link_references = {
        "src/utils/MyLib_1.sol": {"MyLib_1": [{"start": 0, "length": 20}]}
    }
    libs = import_libs(build_out_map, hexcode, link_references)
    assert libs["src/utils/MyLib_1.sol:MyLib_1"]["hexcode"] == "0x1111"

    # 2. Foundry collision artifact for MyLib_1.sol with suffix: utils/MyLib_1.sol_1
    # Stripping .sol_1 must yield utils/MyLib_1.sol without corrupting MyLib_1
    build_out_map_collision = {
        "utils/MyLib_1.sol_1": {"MyLib_1": lib_collision},
    }
    libs = import_libs(build_out_map_collision, hexcode, link_references)
    assert libs["src/utils/MyLib_1.sol:MyLib_1"]["hexcode"] == "0x2222"

    # 3. An artifact named MyLib.sol_1 (collision of MyLib.sol) must NOT match MyLib_1.sol
    build_out_map_other = {
        "utils/MyLib.sol_1": {"MyLib_1": lib_regular},
    }
    # Although contract name matches, recovered basename is MyLib.sol != MyLib_1.sol
    with pytest.raises(HalmosException, match="not found in build output"):
        import_libs(build_out_map_other, hexcode, link_references)


def test_import_libs_missing_ast_multiple_basename_matches_raises():
    # Three candidates have the same contract name and basename, but no distinguishing AST
    lib_a = ({"deployedBytecode": {"object": "0xAAAA"}}, "contract", None)
    lib_b = ({"deployedBytecode": {"object": "0xBBBB"}}, "contract", None)
    lib_c = ({"deployedBytecode": {"object": "0xCCCC"}}, "contract", None)

    build_out_map = {
        "dir_a/Math.sol": {"Math": lib_a},
        "dir_b/Math.sol": {"Math": lib_b},
        "dir_c/Math.sol_2": {"Math": lib_c},
    }

    hexcode = "0x" + "00" * 40
    link_references = {"src/other/Math.sol": {"Math": [{"start": 0, "length": 20}]}}

    with pytest.raises(HalmosException, match="ambiguous library reference") as excinfo:
        import_libs(build_out_map, hexcode, link_references)

    err_msg = str(excinfo.value)
    assert "dir_a/Math.sol" in err_msg
    assert "dir_b/Math.sol" in err_msg
    assert "dir_c/Math.sol_2" in err_msg


def test_import_libs_standard_and_collision_suffix_resolution():
    # Tests resolution across standard paths, nested paths, and collision suffixes
    # both with and without AST absolutePath
    lib_ast = (
        {
            "ast": {"nodeType": "SourceUnit", "absolutePath": "src/nested/Lib.sol"},
            "deployedBytecode": {"object": "0x1111"},
        },
        "contract",
        None,
    )
    lib_collision_ast = (
        {
            "ast": {"nodeType": "SourceUnit", "absolutePath": "src/Colliding.sol"},
            "deployedBytecode": {"object": "0x2222"},
        },
        "contract",
        None,
    )
    lib_collision_no_ast = (
        {"deployedBytecode": {"object": "0x3333"}},
        "contract",
        None,
    )

    build_out_map = {
        "nested/Lib.sol": {"Lib": lib_ast},
        "Colliding.sol_1": {"Colliding": lib_collision_ast},
        "v2/Colliding.sol_2": {"Colliding": lib_collision_no_ast},
    }

    hexcode = "0x" + "00" * 40

    # 1. Resolves nested path with AST
    res1 = import_libs(
        build_out_map,
        hexcode,
        {"src/nested/Lib.sol": {"Lib": [{"start": 0, "length": 20}]}},
    )
    assert res1["src/nested/Lib.sol:Lib"]["hexcode"] == "0x1111"

    # 2. Resolves collision suffix with AST
    res2 = import_libs(
        build_out_map,
        hexcode,
        {"src/Colliding.sol": {"Colliding": [{"start": 0, "length": 20}]}},
    )
    assert res2["src/Colliding.sol:Colliding"]["hexcode"] == "0x2222"

    # 3. Resolves nested collision suffix without AST via path suffix
    res3 = import_libs(
        build_out_map,
        hexcode,
        {"contracts/v2/Colliding.sol": {"Colliding": [{"start": 0, "length": 20}]}},
    )
    assert res3["contracts/v2/Colliding.sol:Colliding"]["hexcode"] == "0x3333"


def test_import_libs_windows_backslashes_in_ast_path():
    # On Windows, AST absolutePath may use backslashes while linkReferences uses forward slashes
    lib = (
        {
            "ast": {"nodeType": "SourceUnit", "absolutePath": "src\\utils\\MyLib.sol"},
            "deployedBytecode": {"object": "0x1234"},
        },
        "contract",
        None,
    )
    build_out_map = {
        "utils/MyLib.sol": {"MyLib": lib},
    }
    hexcode = "0x" + "00" * 40
    link_references = {"src/utils/MyLib.sol": {"MyLib": [{"start": 0, "length": 20}]}}

    libs = import_libs(build_out_map, hexcode, link_references)
    assert libs["src/utils/MyLib.sol:MyLib"]["hexcode"] == "0x1234"


def test_import_libs_duplicate_exact_ast_conflicting_bytecode_raises():
    # Two build_out_map entries share the exact AST path but have conflicting bytecode
    lib_active = (
        {
            "ast": {"nodeType": "SourceUnit", "absolutePath": "src/MyLib.sol"},
            "deployedBytecode": {"object": "0x1111"},
        },
        "contract",
        None,
    )
    lib_stale = (
        {
            "ast": {"nodeType": "SourceUnit", "absolutePath": "src/MyLib.sol"},
            "deployedBytecode": {"object": "0x2222"},
        },
        "contract",
        None,
    )
    build_out_map = {
        "MyLib.sol": {"MyLib": lib_active},
        "stale/MyLib.sol": {"MyLib": lib_stale},
    }
    hexcode = "0x" + "00" * 40
    link_references = {"src/MyLib.sol": {"MyLib": [{"start": 0, "length": 20}]}}

    with pytest.raises(
        HalmosException, match="conflicting exact library artifacts"
    ) as excinfo:
        import_libs(build_out_map, hexcode, link_references)

    err = str(excinfo.value)
    assert "MyLib.sol" in err
    assert "stale/MyLib.sol" in err


def test_import_libs_duplicate_exact_ast_identical_bytecode_resolution():
    lib = (
        {
            "ast": {"nodeType": "SourceUnit", "absolutePath": "src/MyLib.sol"},
            "deployedBytecode": {"object": "0x1111"},
        },
        "contract",
        None,
    )
    # 1. Path-based tie-breaker resolves the correct source artifact
    build_out_map = {
        "MyLib.sol": {"MyLib": lib},
        "backup/MyLib.sol": {"MyLib": lib},
    }
    hexcode = "0x" + "00" * 40
    link_references = {"src/MyLib.sol": {"MyLib": [{"start": 0, "length": 20}]}}
    libs = import_libs(build_out_map, hexcode, link_references)
    assert libs["src/MyLib.sol:MyLib"]["hexcode"] == "0x1111"

    # 2. When artifact identity cannot be uniquely resolved by path, raises HalmosException
    build_out_map_ambiguous = {
        "copy1/MyLib.sol": {"MyLib": lib},
        "copy2/MyLib.sol": {"MyLib": lib},
    }
    with pytest.raises(HalmosException, match="ambiguous library reference"):
        import_libs(build_out_map_ambiguous, hexcode, link_references)
