from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, ForwardRef, Optional

from .exceptions import HalmosException
from .logs import warn

SELECTOR_FIELDS = {
    "VariableDeclaration": "functionSelector",
    "FunctionDefinition": "functionSelector",
    "EventDefinition": "eventSelector",
    "ErrorDefinition": "errorSelector",
}


@dataclass
class AstNode:
    node_type: str
    name: str
    selector: str

    @staticmethod
    def from_dict(node: dict) -> Optional["AstNode"]:
        node_type = node["nodeType"]
        selector_field = SELECTOR_FIELDS.get(node_type)
        if selector_field is None:
            return None

        selector = "0x" + node.get(selector_field, "")
        return AstNode(
            node_type=node_type, name=node.get("name", ""), selector=selector
        )


@dataclass
class ContractMappingInfo:
    contract_name: str
    bytecode: str | None = None

    # indexed by selector
    nodes: dict[str, AstNode] = field(default_factory=dict)

    def with_nodes(self, nodes: list[AstNode]) -> "ContractMappingInfo":
        for node in nodes:
            self.add_node(node)
        return self

    def add_node(self, node: AstNode) -> None:
        # don't overwrite if a node with the same selector already exists
        self.nodes.setdefault(node.selector, node)


@dataclass
class Explanation:
    enabled: bool = False
    content: str = ""

    def add(self, text: str):
        if self.enabled:
            self.content += text

    def print(self):
        if self.enabled:
            print(self.content)

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.print()


class SingletonMeta(type):
    _instances: dict[type, Any] = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)

        return cls._instances[cls]


class BuildOut(metaclass=SingletonMeta):
    def __init__(self):
        self._build_out_map: dict = None
        self._build_out_map_reverse: dict = None
        self._build_out_map_code: dict = None

    def set_build_out(self, build_out_map: dict):
        if self._build_out_map is build_out_map:
            return

        self._build_out_map = build_out_map
        self._build_out_map_reverse = None
        self._build_out_map_code = None

    def create_build_out_map_reverse(self):
        # create reverse mapping
        self._build_out_map_reverse = defaultdict(dict)
        for filename, file_map in self._build_out_map.items():
            for contract_name, (contract_map, _, _) in file_map.items():
                self._build_out_map_reverse[contract_name][filename] = contract_map

    def get_placeholders(self, deployed):
        """
        Extracts a list of placeholders from the deployedBytecode json entry.

        Each placeholder is represented as a tuple of the starting and ending indices.
        These placeholders are used to mark positions for immutables or library addresses within the bytecode.

        The list of placeholders is sorted based on their starting index.

        The method ensures that:
        - There are no overlapping placeholders.
        - The ending index of the last placeholder does not exceed the length of the bytecode.
        """
        placeholders = []

        for links in deployed.get("immutableReferences", {}).values():
            for link in links:
                start = link["start"]
                end = start + link["length"]
                placeholders.append((start, end))

        for libs in deployed.get("linkReferences", {}).values():
            for links in libs.values():
                for link in links:
                    start = link["start"]
                    end = start + link["length"]
                    placeholders.append((start, end))

        placeholders = sorted(placeholders, key=lambda x: x[0])

        # sanity check
        last = 0
        for start, end in placeholders:
            if not (last <= start and start < end):
                raise ValueError("invalid placeholders")
            last = end
        if last > len(deployed["object"][2:]) // 2:
            raise ValueError("invalid placeholders")

        return placeholders

    def create_build_out_map_code(self):
        """
        Creates a mapping between deployed bytecode and contract names.

        This mapping utilizes deployed bytecode because it retains its original length,
        unlike creation bytecode which can be expanded by constructor arguments.

        Since compile-time bytecode may contain placeholders for immutables or library addresses,
        the actual deployed bytecode can differ from its compile-time code.
        To accommodate this, the mapping is constructed from bytecode size to a list of tuples containing bytecode and contract name.
        When querying this mapping, it first retrieves a list of tuples based on their size,
        and then iterates through the list, comparing each bytecode.
        """
        self._build_out_map_code = defaultdict(list)

        for filename, file_map in self._build_out_map.items():
            for contract_name, (contract_map, _, _) in file_map.items():
                deployed = contract_map["deployedBytecode"]
                hexcode = deployed["object"][2:]  # drop '0x' prefix
                if not hexcode:
                    continue

                size = len(hexcode) // 2  # byte length
                placeholders = self.get_placeholders(deployed)
                code_data = (hexcode, placeholders, contract_name, filename)
                self._build_out_map_code[size].append(code_data)

    def get_by_code(self, bytecode: ForwardRef("ByteVec")) -> tuple:
        """
        Return the contract name and file name of the given deployed bytecode.
        """
        if not self._build_out_map_code:
            self.create_build_out_map_code()

        # compares the deployed bytecode with the compile-time hexcode, excluding placeholders from the comparison
        def eq_except_placeholders(hexcode: str, placeholders):
            last = 0
            for start, end in placeholders:
                if not eq_bytes(bytecode[last:start], hexcode[2 * last : 2 * start]):
                    return False
                last = end
            return eq_bytes(bytecode[last:], hexcode[2 * last :])

        def eq_bytes(bytecode: ForwardRef("ByteVec"), hexcode: str):
            bytecode = bytecode.unwrap()
            if not isinstance(bytecode, bytes):
                # non-concrete bytecode chunk cannot be equal to hexcode
                return False
            # bytes.fromhex() should not fail, because the given hexcode chunk does not contain placeholder characters
            return bytecode == bytes.fromhex(hexcode)

        for code_data in self._build_out_map_code[len(bytecode)]:
            hexcode, placeholders, contract_name, filename = code_data
            if eq_except_placeholders(hexcode, placeholders):
                return (contract_name, filename)

        warn(f"unknown deployed bytecode: {bytecode}")
        return (None, None)

    def get_by_name(self, contract_name: str, filename: str = None) -> dict:
        """
        Return the build output json for the given contract name.

        Raise a HalmosException if the contract is not found, or cannot be uniquely determined.

        The optional filename argument is required, if the contract name appears in multiple files.
        """
        if not self._build_out_map_reverse:
            self.create_build_out_map_reverse()

        mapping = self._build_out_map_reverse[contract_name]

        if not mapping:
            raise HalmosException(f"{contract_name} is not found")

        if filename is None:
            if len(mapping) > 1:
                raise HalmosException(
                    f"{contract_name} exists in multiple files: {list(mapping.keys())}"
                )
            [filename] = mapping.keys()

        result = mapping.get(filename)

        if not result:
            raise HalmosException(f"{contract_name} is not found in {filename}")

        return result


class Mapper(metaclass=SingletonMeta):
    """
    Mapping from a contract name to its runtime bytecode and the signatures of functions/events/errors declared in the contract
    """

    _PARSING_IGNORED_NODE_TYPES = [
        "StructDefinition",
        "EnumDefinition",
        "PragmaDirective",
        "ImportDirective",
        "Block",
    ]

    def __init__(self):
        self._contracts: dict[str, ContractMappingInfo] = {}

    def add_mapping(self, mapping: ContractMappingInfo) -> None:
        contract_name = mapping.contract_name
        if contract_name in self._contracts:
            raise ValueError(f"Contract {contract_name} already exists")

        self._contracts[contract_name] = mapping

    def get_or_create(self, contract_name: str) -> ContractMappingInfo:
        if contract_name not in self._contracts:
            self.add_mapping(ContractMappingInfo(contract_name))

        return self._contracts[contract_name]

    def get_by_name(self, contract_name: str) -> ContractMappingInfo | None:
        return self._contracts.get(contract_name, None)

    def get_by_bytecode(self, bytecode: str) -> ContractMappingInfo | None:
        # TODO: Handle cases for contracts with immutable variables
        # Current implementation might not work correctly if the following code is added the test solidity file
        #
        # address immutable public owner;
        # constructor() {
        #     owner = msg.sender;
        # }

        for contract_mapping_info in self._contracts.values():
            # TODO: use regex instaed of `endswith` to better handle immutables or constructors with arguments
            if contract_mapping_info.bytecode.endswith(bytecode):
                return contract_mapping_info

        return None

    def add_node(self, contract_name: str | None, node: AstNode):
        contract_mapping_info = self.get_or_create(contract_name)
        contract_mapping_info.add_node(node)

    def parse_ast(self, node: dict, explain=False):
        # top-level public API meant to be called externally, passing the full AST
        self._parse_ast(node, contract_name=None, explain=explain, _depth=0)

    ### internal methods

    def _parse_ast(
        self, node: dict, contract_name: str | None = None, explain=False, _depth=0
    ):
        node_type = node["nodeType"]
        node_name = node.get("name")
        node_name_str = f": {node_name}" if node_name else ""

        with Explanation(enabled=explain) as expl:
            expl.add(f"{'  ' * _depth}{node_type}{node_name_str}")

            if node_type in self._PARSING_IGNORED_NODE_TYPES:
                expl.add(" (ignored node type)")
                return

            if node_type == "ContractDefinition":
                if contract_name is not None:
                    raise ValueError(f"parsing {contract_name} but found {node}")

                contract_name = node["name"]
                if self.get_or_create(contract_name).nodes:
                    expl.add(" (skipped, already parsed)")
                    return

            ast_node = AstNode.from_dict(node)
            if ast_node and ast_node.selector != "0x":
                self.add_node(contract_name, ast_node)
                expl.add(f" (added node with {ast_node.selector=}")

        # go one level deeper
        for child_node in node.get("nodes", []):
            self._parse_ast(child_node, contract_name, explain, _depth + 1)

        if body := node.get("body"):
            self._parse_ast(body, contract_name, explain, _depth + 1)

    def lookup_selector(self, selector: str, contract_name: str | None = None) -> str:
        if selector == "0x":
            return selector

        # if the given signature is declared in the given contract, return its name.
        if contract_name:
            mapping = self.get_by_name(contract_name)
            if mapping and (node := mapping.nodes.get(selector, None)):
                return node.name

        # otherwise, search for the signature in other contracts and return the first match.
        # note: ambiguity may occur if multiple compilation units exist.
        for mapping in self._contracts.values():
            if node := mapping.nodes.get(selector, None):
                return node.name

        return selector


# TODO: create a new instance or reset for each test
class DeployAddressMapper(metaclass=SingletonMeta):
    """
    Mapping from deployed addresses to contract names
    """

    def __init__(self):
        self._deployed_contracts: dict[str, str] = {}

        # Set up some default mappings
        self.add_deployed_contract("0x7109709ecfa91a80626ff3989d68f67f5b1dd12d", "hevm")
        self.add_deployed_contract("0xf3993a62377bcd56ae39d773740a5390411e8bc9", "svm")
        self.add_deployed_contract("0x636f6e736f6c652e6c6f67", "console")

    def add_deployed_contract(
        self,
        address: str,
        contract_name: str,
    ):
        self._deployed_contracts[address] = contract_name

    def get_deployed_contract(self, address: str) -> str | None:
        return self._deployed_contracts.get(address, address)


def main():
    import json
    import sys

    from .utils import cyan

    def read_json_file(file_path: str) -> dict:
        with open(file_path) as f:
            return json.load(f)

    mapper = Mapper()
    json_out = read_json_file(sys.argv[1])
    mapper.parse_ast(json_out["ast"], explain=True)

    print(cyan("\n### Results ###\n"))
    for contract_name in mapper._contracts:
        print(f"Contract: {contract_name}")
        ast_nodes = mapper.get_by_name(contract_name).nodes
        for selector, node in ast_nodes.items():
            print(f"  {selector}: {node.name}")


if __name__ == "__main__":
    main()
