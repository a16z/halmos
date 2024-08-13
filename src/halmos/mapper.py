from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Type

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
    def from_dict(node: Dict) -> Optional["AstNode"]:
        node_type = node["nodeType"]
        selector_field = SELECTOR_FIELDS.get(node_type, None)
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
    nodes: Dict[str, AstNode] = field(default_factory=dict)

    def with_nodes(self, nodes: List[AstNode]) -> "ContractMappingInfo":
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
    _instances: Dict[Type, Any] = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            cls._instances[cls] = super().__call__(*args, **kwargs)

        return cls._instances[cls]


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
        self._contracts: Dict[str, ContractMappingInfo] = {}

    def add_mapping(self, mapping: ContractMappingInfo) -> None:
        contract_name = mapping.contract_name
        if contract_name in self._contracts:
            raise ValueError(f"Contract {contract_name} already exists")

        self._contracts[contract_name] = mapping

    def get_or_create(self, contract_name: str) -> ContractMappingInfo:
        if contract_name not in self._contracts:
            self.add_mapping(ContractMappingInfo(contract_name))

        return self._contracts[contract_name]

    def get_by_name(self, contract_name: str) -> Optional[ContractMappingInfo]:
        return self._contracts.get(contract_name, None)

    def get_by_bytecode(self, bytecode: str) -> Optional[ContractMappingInfo]:
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

    def parse_ast(self, node: Dict, explain=False):
        # top-level public API meant to be called externally, passing the full AST
        self._parse_ast(node, contract_name=None, explain=explain, _depth=0)

    ### internal methods

    def _parse_ast(
        self, node: Dict, contract_name: str | None = None, explain=False, _depth=0
    ):
        node_type = node["nodeType"]
        node_name = node.get("name", None)
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

        if body := node.get("body", None):
            self._parse_ast(body, contract_name, explain, _depth + 1)

    def lookup_selector(self, selector: str, contract_name: str | None = None) -> str:
        if selector == "0x":
            return selector

        # if the given signature is declared in the given contract, return its name.
        if contract_name:
            contract_mapping_info = self.get_by_name(contract_name)
            if contract_mapping_info:
                if node := contract_mapping_info.nodes.get(selector, None):
                    return node.name

        # otherwise, search for the signature in other contracts and return the first match.
        # note: ambiguity may occur if multiple compilation units exist.
        for contract_mapping_info in self._contracts.values():
            if node := contract_mapping_info.nodes.get(selector, None):
                return node.name

        return selector


# TODO: create a new instance or reset for each test
class DeployAddressMapper(metaclass=SingletonMeta):
    """
    Mapping from deployed addresses to contract names
    """

    def __init__(self):
        self._deployed_contracts: Dict[str, str] = {}

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

    def get_deployed_contract(self, address: str) -> Optional[str]:
        return self._deployed_contracts.get(address, address)


def main():
    import sys
    import json
    from .utils import cyan

    def read_json_file(file_path: str) -> Dict:
        with open(file_path) as f:
            return json.load(f)

    mapper = Mapper()
    json_out = read_json_file(sys.argv[1])
    mapper.parse_ast(json_out["ast"], explain=True)

    print(cyan("\n### Results ###\n"))
    for contract_name in mapper._contracts.keys():
        print(f"Contract: {contract_name}")
        ast_nodes = mapper.get_by_name(contract_name).nodes
        for selector, node in ast_nodes.items():
            print(f"  {selector}: {node.name}")


if __name__ == "__main__":
    main()
