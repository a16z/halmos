# SPDX-License-Identifier: AGPL-3.0

import json
import os
import re
import traceback

from halmos.config import Config as HalmosConfig
from halmos.logs import PARSING_ERROR, debug, warn_code
from halmos.mapper import Mapper, SourceFileMap
from halmos.ui import ui


def get_contract_type(
    ast_nodes: list, contract_name: str
) -> tuple[str | None, str | None]:
    for node in ast_nodes:
        if node["nodeType"] == "ContractDefinition" and node["name"] == contract_name:
            abstract = "abstract " if node.get("abstract") else ""
            contract_type = abstract + node["contractKind"]
            natspec = node.get("documentation")
            return contract_type, natspec

    return None, None


def parse_build_out(args: HalmosConfig) -> dict:
    result = {}  # compiler version -> source filename -> contract name -> (json, type)

    coverage_output = args.coverage_output
    root = args.root

    if coverage_output:
        SourceFileMap().set_root(root)

    out_path = os.path.join(root, args.forge_build_out)
    if not os.path.exists(out_path):
        raise FileNotFoundError(
            f"The build output directory `{out_path}` does not exist"
        )

    ui.update_status(f"Parsing {out_path}")
    for sol_dirname in os.listdir(out_path):  # for each source filename
        if not sol_dirname.endswith(".sol"):
            continue

        sol_path = os.path.join(out_path, sol_dirname)
        if not os.path.isdir(sol_path):
            continue

        for json_filename in os.listdir(sol_path):  # for each contract name
            try:
                if not json_filename.endswith(".json"):
                    continue
                if json_filename.startswith("."):
                    continue

                json_path = os.path.join(sol_path, json_filename)
                with open(json_path, encoding="utf8") as f:
                    json_out = json.load(f)

                ast = json_out["ast"]

                if coverage_output:
                    # record the mapping between file id and file path
                    SourceFileMap().add_mapping(json_out["id"], ast["absolutePath"])

                # cut off compiler version number as well
                contract_name = json_filename.split(".")[0]
                ast_nodes = ast["nodes"]
                contract_type, natspec = get_contract_type(ast_nodes, contract_name)

                # can happen to solidity files for multiple reasons:
                # - import only (like console2.log)
                # - defines only structs or enums
                # - defines only free functions
                # - ...
                if contract_type is None:
                    debug(f"Skipped {json_filename}, no contract definition found")
                    continue

                compiler_version = json_out["metadata"]["compiler"]["version"]
                result.setdefault(compiler_version, {})
                result[compiler_version].setdefault(sol_dirname, {})
                contract_map = result[compiler_version][sol_dirname]

                if contract_name in contract_map:
                    raise ValueError(
                        "duplicate contract names in the same file",
                        contract_name,
                        sol_dirname,
                    )

                contract_map[contract_name] = (json_out, contract_type, natspec)
                parse_symbols(args, contract_map, contract_name)

            except Exception as err:
                warn_code(
                    PARSING_ERROR,
                    f"Skipped {json_filename} due to parsing failure: {type(err).__name__}: {err}",
                )
                if args.debug:
                    traceback.print_exc()
                continue

    return result


def parse_symbols(args: HalmosConfig, contract_map: dict, contract_name: str) -> None:
    try:
        json_out = contract_map[contract_name][0]

        # workaround: solx does not emit bytecode at all for library contracts
        # default to an empty object to emulate solc behavior
        bytecode = json_out.get("bytecode", {"object": "0x"})["object"]
        contract_mapping_info = Mapper().get_or_create(contract_name)
        contract_mapping_info.bytecode = bytecode

        Mapper().parse_ast(json_out["ast"])

    except Exception:
        debug(f"error parsing symbols for contract {contract_name}")
        debug(traceback.format_exc())

        # we parse symbols as best effort, don't propagate exceptions
        pass


def parse_devdoc(funsig: str, contract_json: dict) -> str | None:
    try:
        return contract_json["metadata"]["output"]["devdoc"]["methods"][funsig][
            "custom:halmos"
        ]
    except KeyError:
        return None


def parse_natspec(natspec: dict) -> str:
    # This parsing scheme is designed to handle:
    #
    # - multiline tags:
    #   /// @custom:halmos --x
    #   ///                --y
    #
    # - multiple tags:
    #   /// @custom:halmos --x
    #   /// @custom:halmos --y
    #
    # - tags that start in the middle of line:
    #   /// blah blah @custom:halmos --x
    #   /// --y
    #
    # In all the above examples, this scheme returns "--x (whitespaces) --y"
    isHalmosTag = False
    result = ""
    for item in re.split(r"(@\S+)", natspec.get("text", "")):
        if item == "@custom:halmos":
            isHalmosTag = True
        elif re.match(r"^@\S", item):
            isHalmosTag = False
        elif isHalmosTag:
            result += item
    return result.strip()


def import_libs(build_out_map: dict, hexcode: str, linkReferences: dict) -> dict:
    libs = {}

    for filepath in linkReferences:
        file_name = filepath.split("/")[-1]

        for lib_name in linkReferences[filepath]:
            (lib_json, _, _) = build_out_map[file_name][lib_name]
            lib_hexcode = lib_json["deployedBytecode"]["object"]

            # in bytes, multiply indices by 2 and offset 0x
            placeholder_index = linkReferences[filepath][lib_name][0]["start"] * 2 + 2
            placeholder = hexcode[placeholder_index : placeholder_index + 40]

            libs[f"{filepath}:{lib_name}"] = {
                "placeholder": placeholder,
                "hexcode": lib_hexcode,
            }

    return libs


def build_output_iterator(build_out: dict):
    for compiler_version in sorted(build_out):
        build_out_map = build_out[compiler_version]
        for filename in sorted(build_out_map):
            for contract_name in sorted(build_out_map[filename]):
                yield (build_out_map, filename, contract_name)
