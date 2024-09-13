from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Optional

from .exceptions import HalmosException

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

    def set_build_out(self, build_out_map: dict):
        if self._build_out_map is build_out_map:
            return

        self._build_out_map = build_out_map
        self._build_out_map_reverse = None

    def create_build_out_map_reverse(self):
        # create reverse mapping
        self._build_out_map_reverse = defaultdict(dict)
        for filename, file_map in self._build_out_map.items():
            for contract_name, contract_map in file_map.items():
                self._build_out_map_reverse[contract_name][filename] = contract_map

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
