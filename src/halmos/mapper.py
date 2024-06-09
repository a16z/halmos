from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Type


@dataclass
class AstNode:
    node_type: str
    id: int
    name: str
    address: str
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

    def get_contarct_mapping_info_by_bytecode(
        self, bytecode: str
    ) -> Optional[ContractMappingInfo]:
        for contract_mapping_info in self._contracts.values():
            if contract_mapping_info.bytecode == bytecode:
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
