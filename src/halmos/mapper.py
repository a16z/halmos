from dataclasses import dataclass
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
    id: int
    name: str
    address: str  # TODO: rename it to `selector` or `signature` to better reflect the meaning
    visibility: str


@dataclass
class ContractMappingInfo:
    contract_name: str
    bytecode: str
    nodes: List[AstNode]


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

    def add(self, contract_name: str, bytecode: str, nodes: List[AstNode]):
        if contract_name in self._contracts:
            raise ValueError(f"Contract {contract_name} already exists")

        value = ContractMappingInfo(contract_name, bytecode, nodes)
        self._contracts[contract_name] = value

    def get_or_create(self, contract_name: str) -> ContractMappingInfo:
        if contract_name not in self._contracts:
            self.add(contract_name, "", [])

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

    def append_node(self, contract_name: str, node: AstNode):
        contract_mapping_info = self.get_or_create(contract_name)
        contract_mapping_info.nodes.append(node)

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

            id, name, selector, visibility = self._get_node_info(node)
            if selector != "0x":
                ast_node = AstNode(node_type, id, name, selector, visibility)
                self.append_node(contract_name, ast_node)
                expl.add(f" (added node with {selector=}")

        # go one level deeper
        for child_node in node.get("nodes", []):
            self._parse_ast(child_node, contract_name, explain, _depth + 1)

        if body := node.get("body", None):
            self._parse_ast(body, contract_name, explain, _depth + 1)

    def _get_node_info(self, node: Dict) -> Dict:
        return (
            node.get("id", ""),
            node.get("name", ""),
            "0x" + self._get_node_selector(node),
            node.get("visibility", ""),
        )

    def _get_node_selector(self, node: Dict) -> str:
        node_type = node["nodeType"]
        if not (selector_field := SELECTOR_FIELDS.get(node_type, None)):
            return ""

        # free functions don't have a function selector
        return node.get(selector_field, "")

    def find_nodes_by_address(self, address: str, contract_name: str = None):
        # if the given signature is declared in the given contract, return its name.
        if contract_name:
            contract_mapping_info = self.get_by_name(contract_name)

            if contract_mapping_info:
                for node in contract_mapping_info.nodes:
                    if node.address == address:
                        return node.name

        # otherwise, search for the signature in other contracts, and return all the contracts that declare it.
        # note: ambiguity may occur if multiple compilation units exist.
        result = ""
        for key, contract_info in self._contracts.items():
            matching_nodes = [
                node for node in contract_info.nodes if node.address == address
            ]

            for node in matching_nodes:
                result += f"{key}.{node.name} "

        return result.strip() if result != "" and address != "0x" else address


# TODO: create a new instance or reset for each test
class DeployAddressMapper(metaclass=SingletonMeta):
    """
    Mapping from deployed addresses to contract names
    """

    def __init__(self):
        self._deployed_contracts: Dict[str, str] = {}

        # Set up some default mappings
        self.add_deployed_contract(
            "0x7109709ecfa91a80626ff3989d68f67f5b1dd12d", "HEVM_ADDRESS"
        )
        self.add_deployed_contract(
            "0xf3993a62377bcd56ae39d773740a5390411e8bc9", "SVM_ADDRESS"
        )

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
        for node in ast_nodes:
            print(f"  {node}")


if __name__ == "__main__":
    main()
