from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Type


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

    def add_contract_mapping_info(
        self, contract_name: str, bytecode: str, nodes: List[AstNode]
    ):
        if contract_name in self._contracts:
            raise ValueError(f"Contract {contract_name} already exists")

        self._contracts[contract_name] = ContractMappingInfo(
            contract_name, bytecode, nodes
        )

    def get_contract_mapping_info_by_name(
        self, contract_name: str
    ) -> Optional[ContractMappingInfo]:
        return self._contracts.get(contract_name, None)

    def get_contract_mapping_info_by_bytecode(
        self, bytecode: str
    ) -> Optional[ContractMappingInfo]:
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
        contract_mapping_info = self.get_contract_mapping_info_by_name(contract_name)

        if contract_mapping_info is None:
            raise ValueError(f"Contract {contract_name} not found")

        contract_mapping_info.nodes.append(node)

    def parse_ast(self, node: Dict, contract_name: str = ""):
        node_type = node["nodeType"]

        if node_type in self._PARSING_IGNORED_NODE_TYPES:
            return

        current_contract = self._get_current_contract(node, contract_name)

        if node_type == "ContractDefinition":
            if current_contract not in self._contracts:
                self.add_contract_mapping_info(
                    contract_name=current_contract, bytecode="", nodes=[]
                )

            if self.get_contract_mapping_info_by_name(current_contract).nodes:
                return
        elif node_type != "SourceUnit":
            id, name, address, visibility = self._get_node_info(node, node_type)

            self.append_node(
                current_contract,
                AstNode(node_type, id, name, address, visibility),
            )

        for child_node in node.get("nodes", []):
            self.parse_ast(child_node, current_contract)

        if "body" in node:
            self.parse_ast(node["body"], current_contract)

    def _get_node_info(self, node: Dict, node_type: str) -> Dict:
        return (
            node.get("id", ""),
            node.get("name", ""),
            "0x" + self._get_node_address(node, node_type),
            node.get("visibility", ""),
        )

    def _get_node_address(self, node: Dict, node_type: str) -> str:
        address_fields = {
            "VariableDeclaration": "functionSelector",
            "FunctionDefinition": "functionSelector",
            "EventDefinition": "eventSelector",
            "ErrorDefinition": "errorSelector",
        }

        return node.get(address_fields.get(node_type, ""), "")

    def _get_current_contract(self, node: Dict, contract_name: str) -> str:
        return (
            node.get("name", "")
            if node["nodeType"] == "ContractDefinition"
            else contract_name
        )

    def find_nodes_by_address(self, address: str, contract_name: str = None):
        # if the given signature is declared in the given contract, return its name.
        if contract_name:
            contract_mapping_info = self.get_contract_mapping_info_by_name(
                contract_name
            )

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
