# SPDX-License-Identifier: AGPL-3.0

import json
import os
import posixpath
import re
import traceback

from eth_hash.auto import keccak

from dolmos.calldata import str_abi
from dolmos.config import Config as DolmosConfig
from dolmos.logs import PARSING_ERROR, debug, warn_code
from dolmos.mapper import Mapper, SourceFileMap
from dolmos.ui import ui

SOLIDITY_EXTENSIONS = (".sol",)
VYPER_EXTENSIONS = (".vy", ".vyi")

# build output groups are keyed by compiler version; vyper groups get this prefix
# so that they never collide with solc versions (e.g. vyper 0.4.3 vs solc 0.4.3)
VYPER_VERSION_PREFIX = "vyper:"

FORGE_CACHE_FILE = os.path.join("cache", "solidity-files-cache.json")


def is_vyper_file(filename: str) -> bool:
    return filename.endswith(VYPER_EXTENSIONS)


def is_vyper_group(compiler_version: str) -> bool:
    return compiler_version.startswith(VYPER_VERSION_PREFIX)


def is_vyper_contract(contract_json: dict) -> bool:
    return contract_json.get("language") == "vyper"


def get_source_path(contract_json: dict, default: str | None = None) -> str | None:
    """
    Return the source path of a build artifact (e.g. `test/Foo.t.sol`).

    solc artifacts carry it in their AST; vyper artifacts get it from the forge
    cache during normalization (see `normalize_vyper_artifact`).
    """
    if path := contract_json.get("sourcePath"):
        return path
    try:
        return contract_json["ast"]["absolutePath"]
    except (KeyError, TypeError):
        return default


def _artifact_key(path: str) -> str:
    """Normalize an artifact path to a platform-independent key (`/` separators)."""
    return posixpath.normpath(path.replace("\\", "/"))


def load_forge_cache(root: str, out_path: str) -> dict:
    """
    Return a mapping from artifact path (relative to the build output directory,
    e.g. `Counter.vy/Counter.json`) to a (source path, compiler version) pair.

    Vyper artifacts emitted by forge only contain the abi and the bytecode, so the
    forge cache is the only place where the source path and compiler version live.
    Best effort: returns an empty mapping if the cache is missing or unreadable.
    """
    cache_path = os.path.join(root, FORGE_CACHE_FILE)
    result = {}

    try:
        with open(cache_path, encoding="utf8") as f:
            cache = json.load(f)
    except (OSError, ValueError) as err:
        debug(f"could not read forge cache {cache_path}: {err}")
        return result

    for source_path, entry in cache.get("files", {}).items():
        for versions in entry.get("artifacts", {}).values():
            for version, profiles in versions.items():
                for artifact in profiles.values():
                    artifact_path = artifact.get("path")
                    if not artifact_path:
                        continue
                    # paths are relative to the out dir; tolerate an `out/` prefix
                    artifact_path = _artifact_key(artifact_path)
                    out_prefix = os.path.basename(os.path.normpath(out_path)) + "/"
                    if artifact_path.startswith(out_prefix):
                        artifact_path = artifact_path[len(out_prefix) :]
                    result[artifact_path] = (source_path, version)

    return result


_DOCSTRING = r'(?:"""(?P<doc>.*?)"""|\'\'\'(?P<doc2>.*?)\'\'\')'

# module docstring: the first string literal of the file, possibly after comments
# such as `# pragma version ...`
_VYPER_MODULE_DOCSTRING = re.compile(r"\A(?:\s*#[^\n]*\n|\s+)*" + _DOCSTRING, re.DOTALL)

# function docstring: first string literal right after the (possibly multiline) signature
_VYPER_FUNCTION_DOCSTRING = re.compile(
    r"^[ \t]*def[ \t]+(?P<name>\w+)[ \t]*\((?:[^()]|\([^()]*\))*\)"
    r"(?:[ \t]*->[^:\n]+)?[ \t]*:[ \t]*(?:#[^\n]*)?\n\s*" + _DOCSTRING,
    re.DOTALL | re.MULTILINE,
)


def _docstring_text(match: re.Match) -> str:
    return match.group("doc") if match.group("doc") is not None else match.group("doc2")


def parse_vyper_docstrings(source: str) -> tuple[str | None, dict[str, str]]:
    """
    Extract the module docstring and the per-function docstrings of a vyper source.

    Returns (module docstring or None, function name -> docstring).
    """
    module_doc = None
    if match := _VYPER_MODULE_DOCSTRING.match(source):
        module_doc = _docstring_text(match)

    function_docs = {}
    for match in _VYPER_FUNCTION_DOCSTRING.finditer(source):
        function_docs.setdefault(match.group("name"), _docstring_text(match))

    return module_doc, function_docs


def normalize_vyper_artifact(
    json_out: dict, dirname: str, root: str, cache_entry
) -> tuple[str, str, dict | None]:
    """
    Bring a forge vyper artifact into the shape that dolmos expects from solc artifacts.

    forge only emits `abi`, `bytecode`, `deployedBytecode`, an empty `methodIdentifiers`
    and an `id` for vyper, so we fill in:
    - `methodIdentifiers`, computed from the abi
    - `bytecode.linkReferences` (vyper has no libraries)
    - `metadata.compiler.version` and `metadata.output.devdoc` (for `@custom:dolmos`)
    - `sourcePath` and `language`

    Returns (contract type, compiler version group key, natspec).
    """
    source_path, version = cache_entry if cache_entry else (dirname, "unknown")

    json_out["language"] = "vyper"
    json_out["sourcePath"] = source_path

    if not json_out.get("methodIdentifiers"):
        json_out["methodIdentifiers"] = {
            (sig := str_abi(item)): keccak(sig.encode()).hex()[:8]
            for item in json_out.get("abi", [])
            if item.get("type") == "function"
        }

    for key in ("bytecode", "deployedBytecode"):
        entry = json_out.get(key)
        if isinstance(entry, str):
            entry = {"object": entry}
        entry = entry or {"object": "0x"}
        entry.setdefault("object", "0x")
        entry.setdefault("linkReferences", {})
        json_out[key] = entry

    # vyper modules are always contracts, .vyi files are always interfaces
    contract_type = "interface" if dirname.endswith(".vyi") else "contract"

    # `@custom:dolmos` annotations live in docstrings; forge does not give us the
    # devdoc for vyper, so read them straight from the source
    natspec = None
    devdoc_methods = {}
    try:
        with open(os.path.join(root, source_path), encoding="utf8") as f:
            module_doc, function_docs = parse_vyper_docstrings(f.read())

        if module_doc:
            natspec = {"text": module_doc}

        for funsig in json_out["methodIdentifiers"]:
            doc = function_docs.get(funsig.split("(")[0])
            if doc and (options := parse_natspec({"text": doc})):
                devdoc_methods[funsig] = {"custom:dolmos": options}
    except OSError as err:
        debug(f"could not read vyper source {source_path}: {err}")

    metadata = json_out.setdefault("metadata", {})
    metadata.setdefault("compiler", {}).setdefault("version", version)
    metadata.setdefault("output", {}).setdefault("devdoc", {}).setdefault(
        "methods", {}
    ).update(devdoc_methods)

    return contract_type, VYPER_VERSION_PREFIX + version, natspec


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


ARTIFACT_EXTENSIONS = SOLIDITY_EXTENSIONS + VYPER_EXTENSIONS

# subdirectories of the build output that never hold contract artifacts
NON_ARTIFACT_DIRS = ("build-info",)


def iter_artifact_dirs(out_path: str):
    """
    Yield (relative path, absolute path) for every artifact directory of the build
    output, i.e. every directory named after a source file (`Foo.sol`, `Foo.vy`).

    forge writes the artifacts of `src/Foo.sol` to `out/Foo.sol/`, unless another
    source file with the same name already claimed that directory: it then adds
    parent directories of the source path until the path is unique, e.g.
    `out/nested/Foo.sol/` for `src/nested/Foo.sol` (forge's
    `conflict_free_output_file`). These nested directories must be found as well
    (halmos#582).

    The relative path uses `/` separators on every platform, and is just the
    directory name for top-level artifact directories. The traversal is sorted, so
    the result does not depend on the order of `os.listdir`.
    """
    for dirpath, dirnames, _ in os.walk(out_path):
        rel_dir = os.path.relpath(dirpath, out_path)
        if rel_dir == ".":
            dirnames[:] = [d for d in dirnames if d not in NON_ARTIFACT_DIRS]
        dirnames.sort()

        # an artifact directory only holds json files, don't descend into it
        descend = []
        for dirname in dirnames:
            if dirname.endswith(ARTIFACT_EXTENSIONS):
                rel_path = dirname if rel_dir == "." else f"{rel_dir}/{dirname}"
                yield _artifact_key(rel_path), os.path.join(dirpath, dirname)
            else:
                descend.append(dirname)
        dirnames[:] = descend


def find_contract(build_out_map: dict, source_path: str, contract_name: str):
    """
    Return the build output entry (json, type, natspec) of a contract, given the
    path of its source file (e.g. `src/nested/Lib.sol`, as found in
    `linkReferences`), or None if it is not found.

    The entry is normally stored under the file name (`Lib.sol`), but under a longer
    path when forge resolved a name conflict (see `iter_artifact_dirs`), so the
    source path recorded in the artifact decides between candidates.
    """
    source_path = _artifact_key(source_path)
    basename = posixpath.basename(source_path)

    candidates = [
        contracts[contract_name]
        for filename, contracts in build_out_map.items()
        if posixpath.basename(filename) == basename and contract_name in contracts
    ]

    for entry in candidates:
        path = get_source_path(entry[0])
        if path is not None and _artifact_key(path) == source_path:
            return entry

    # artifacts without a source path: only accept an unambiguous match
    return candidates[0] if len(candidates) == 1 else None


def _artifact_json_in(dir_path: str, contract_name: str) -> str | None:
    """
    Return the artifact of a contract in an artifact directory: `Name.json`, or
    `Name.<compiler version>.json` when it was compiled with several compiler versions
    and there is only one such file.
    """
    plain = os.path.join(dir_path, f"{contract_name}.json")
    if os.path.isfile(plain):
        return plain
    versioned = [
        f
        for f in os.listdir(dir_path)
        if f.startswith(f"{contract_name}.") and f.endswith(".json")
    ]
    if len(versioned) == 1:
        return os.path.join(dir_path, versioned[0])
    return None


def resolve_artifact_path(out_path: str, source: str, contract_name: str) -> str:
    """
    Return the path of the artifact of `contract_name`, defined in the source file
    `source`, which is either a file name (`Foo.sol`) or a path (`src/nested/Foo.sol`),
    as accepted by `vm.getCode`.

    The artifact is normally `out/Foo.sol/Name.json`, but forge moves it to e.g.
    `out/nested/Foo.sol/Name.json` when another `Foo.sol` exists (halmos#582). With a
    path, the artifact whose source path matches it is chosen; with a file name, the
    match must be unique, as in foundry.
    """
    source = _artifact_key(source)
    basename = posixpath.basename(source)

    candidates = []
    for rel_path, dir_path in iter_artifact_dirs(out_path):
        if posixpath.basename(rel_path) != basename:
            continue
        if json_path := _artifact_json_in(dir_path, contract_name):
            candidates.append(json_path)

    if not candidates:
        raise FileNotFoundError(
            f"no artifact found for {source}:{contract_name} in {out_path}"
        )

    if len(candidates) == 1:
        return candidates[0]

    if source != basename:
        for json_path in candidates:
            try:
                with open(json_path, encoding="utf8") as f:
                    path = get_source_path(json.load(f))
            except (OSError, ValueError):
                continue
            if path is not None and (
                _artifact_key(path) == source
                or _artifact_key(path).endswith("/" + source)
            ):
                return json_path

    rel_candidates = sorted(
        _artifact_key(os.path.relpath(c, out_path)) for c in candidates
    )
    raise ValueError(
        f"multiple artifacts match {source}:{contract_name}: "
        + ", ".join(rel_candidates)
        + "; use the full source path, e.g. `src/dir/File.sol:Name`"
    )


def parse_build_out(args: DolmosConfig) -> dict:
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

    # only needed for vyper artifacts, loaded lazily
    forge_cache = None

    # for each source filename; `sol_dirname` is the path of the artifact directory
    # relative to the build output, e.g. `Foo.sol`, or `nested/Foo.sol` for artifacts
    # that forge moved to a subdirectory to resolve a name conflict
    for sol_dirname, sol_path in iter_artifact_dirs(out_path):
        for json_filename in sorted(os.listdir(sol_path)):  # for each contract name
            try:
                if not json_filename.endswith(".json"):
                    continue
                if json_filename.startswith("."):
                    continue

                json_path = os.path.join(sol_path, json_filename)
                with open(json_path, encoding="utf8") as f:
                    json_out = json.load(f)

                # cut off compiler version number as well
                contract_name = json_filename.split(".")[0]

                if is_vyper_file(sol_dirname):
                    if forge_cache is None:
                        forge_cache = load_forge_cache(root, out_path)

                    cache_entry = forge_cache.get(
                        _artifact_key(f"{sol_dirname}/{json_filename}")
                    )
                    contract_type, compiler_version, natspec = normalize_vyper_artifact(
                        json_out, posixpath.basename(sol_dirname), root, cache_entry
                    )

                    # note: coverage is not supported for vyper (no source maps),
                    # and vyper file ids would clash with solc ones
                    add_to_build_out(
                        result,
                        compiler_version,
                        sol_dirname,
                        contract_name,
                        (json_out, contract_type, natspec),
                    )
                    parse_symbols(
                        args, result[compiler_version][sol_dirname], contract_name
                    )
                    continue

                ast = json_out["ast"]

                if coverage_output:
                    # record the mapping between file id and file path
                    SourceFileMap().add_mapping(json_out["id"], ast["absolutePath"])

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
                add_to_build_out(
                    result,
                    compiler_version,
                    sol_dirname,
                    contract_name,
                    (json_out, contract_type, natspec),
                )
                parse_symbols(
                    args, result[compiler_version][sol_dirname], contract_name
                )

            except Exception as err:
                warn_code(
                    PARSING_ERROR,
                    f"Skipped {json_filename} due to parsing failure: {type(err).__name__}: {err}",
                )
                if args.debug:
                    traceback.print_exc()
                continue

    ui.stop_status()
    return result


def add_to_build_out(
    result: dict, compiler_version: str, filename: str, contract_name: str, entry
) -> None:
    contract_map = result.setdefault(compiler_version, {}).setdefault(filename, {})

    if contract_name in contract_map:
        raise ValueError(
            "duplicate contract names in the same file",
            contract_name,
            filename,
        )

    contract_map[contract_name] = entry


def parse_symbols(args: DolmosConfig, contract_map: dict, contract_name: str) -> None:
    try:
        json_out = contract_map[contract_name][0]

        # workaround: solx does not emit bytecode at all for library contracts
        # default to an empty object to emulate solc behavior
        bytecode = json_out.get("bytecode", {"object": "0x"})["object"]
        contract_mapping_info = Mapper().get_or_create(contract_name)
        contract_mapping_info.bytecode = bytecode

        # vyper artifacts have no (solc-style) ast
        if "ast" in json_out:
            Mapper().parse_ast(json_out["ast"])

    except Exception:
        debug(f"error parsing symbols for contract {contract_name}")
        debug(traceback.format_exc())

        # we parse symbols as best effort, don't propagate exceptions
        pass


# natspec tags carrying command line options; @custom:halmos is still accepted so
# that test suites written for halmos keep working unchanged
NATSPEC_TAGS = ("dolmos", "halmos")


def parse_devdoc(funsig: str, contract_json: dict) -> str | None:
    try:
        method_doc = contract_json["metadata"]["output"]["devdoc"]["methods"][funsig]
    except KeyError:
        return None

    values = [
        method_doc[f"custom:{tag}"]
        for tag in NATSPEC_TAGS
        if f"custom:{tag}" in method_doc
    ]
    return " ".join(values) if values else None


def parse_natspec(natspec: dict) -> str:
    # This parsing scheme is designed to handle:
    #
    # - multiline tags:
    #   /// @custom:dolmos --x
    #   ///                --y
    #
    # - multiple tags:
    #   /// @custom:dolmos --x
    #   /// @custom:dolmos --y
    #
    # - tags that start in the middle of line:
    #   /// blah blah @custom:dolmos --x
    #   /// --y
    #
    # In all the above examples, this scheme returns "--x (whitespaces) --y"
    # (@custom:halmos is accepted as well, see NATSPEC_TAGS)
    tags = {f"@custom:{tag}" for tag in NATSPEC_TAGS}
    is_options_tag = False
    result = ""
    for item in re.split(r"(@\S+)", natspec.get("text", "")):
        if item in tags:
            is_options_tag = True
        elif re.match(r"^@\S", item):
            is_options_tag = False
        elif is_options_tag:
            result += item
    return result.strip()


def import_libs(build_out_map: dict, hexcode: str, linkReferences: dict) -> dict:
    libs = {}

    for filepath in linkReferences:
        for lib_name in linkReferences[filepath]:
            entry = find_contract(build_out_map, filepath, lib_name)
            if entry is None:
                raise ValueError(f"library {filepath}:{lib_name} not found")
            (lib_json, _, _) = entry
            lib_hexcode = lib_json["deployedBytecode"]["object"]

            # in bytes, multiply indices by 2 and offset 0x
            placeholder_index = linkReferences[filepath][lib_name][0]["start"] * 2 + 2
            placeholder = hexcode[placeholder_index : placeholder_index + 40]

            libs[f"{filepath}:{lib_name}"] = {
                "placeholder": placeholder,
                "hexcode": lib_hexcode,
            }

    return libs


def has_vyper_contracts(build_out: dict) -> bool:
    return any(is_vyper_group(version) for version in build_out)


def build_out_view(build_out: dict, compiler_version: str) -> dict:
    """
    Return the build output map visible to test contracts of the given group.

    Test contracts normally only see contracts compiled with the same compiler version
    (e.g. for library linking and bytecode lookups). Cross-language setups are common
    though (solidity tests for vyper contracts, and vice versa), so:
    - solidity groups also see every vyper contract
    - vyper groups see every vyper contract, and the solidity contracts if there is
      a single solc version (otherwise the lookup would be ambiguous)

    Solidity and vyper filenames can't collide since they have different extensions.
    """
    own = build_out[compiler_version]
    vyper_groups = [v for v in build_out if is_vyper_group(v)]
    solc_groups = [v for v in build_out if not is_vyper_group(v)]

    if is_vyper_group(compiler_version):
        shared = [v for v in vyper_groups if v != compiler_version]
        if len(solc_groups) == 1:
            shared += solc_groups
    else:
        shared = vyper_groups

    if not shared:
        return own

    view = dict(own)
    for version in sorted(shared):
        for filename, contracts in build_out[version].items():
            view.setdefault(filename, contracts)
    return view


def build_output_iterator(build_out: dict):
    for compiler_version in sorted(build_out):
        build_out_map = build_out[compiler_version]

        # computed once per group, so that the BuildOut singleton can cache it
        view = build_out_view(build_out, compiler_version)

        for filename in sorted(build_out_map):
            for contract_name in sorted(build_out_map[filename]):
                yield (view, filename, contract_name)
