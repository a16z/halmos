from typing import List

import pytest

from halmos.mapper import AstNode, ContractMappingInfo, Mapper, SingletonMeta


@pytest.fixture
def ast_nodes() -> List[AstNode]:
    return [
        AstNode(
            node_type="type1", id=1, name="Node1", address="0x123", visibility="public"
        ),
        AstNode(
            node_type="type2", id=2, name="Node2", address="0x456", visibility="private"
        ),
    ]


@pytest.fixture
def mapper() -> Mapper:
    return Mapper()


@pytest.fixture(autouse=True)
def reset_singleton():
    SingletonMeta._instances = {}


def test_singleton():
    mapper1 = Mapper()
    mapper2 = Mapper()
    assert mapper1 is mapper2


def test_add(mapper, ast_nodes):
    mapper.add("ContractA", "bytecodeA", ast_nodes)
    contract_info = mapper.get_by_name("ContractA")
    assert contract_info is not None
    assert contract_info.contract_name == "ContractA"
    assert contract_info.bytecode == "bytecodeA"
    assert len(contract_info.nodes) == 2


def test_add_already_existence(mapper, ast_nodes):
    mapper.add("ContractA", "bytecodeA", ast_nodes)

    with pytest.raises(ValueError, match=r"Contract ContractA already exists"):
        mapper.add("ContractA", "bytecodeA", ast_nodes)


def test_get_by_name(mapper, ast_nodes):
    mapper.add("ContractA", "bytecodeA", ast_nodes)
    contract_info = mapper.get_by_name("ContractA")
    assert contract_info is not None
    assert contract_info.contract_name == "ContractA"


def test_get_by_name_nonexistent(mapper):
    contract_info = mapper.get_by_name("ContractA")
    assert contract_info is None


def test_get_by_bytecode(mapper, ast_nodes):
    mapper.add("ContractA", "bytecodeA", ast_nodes)
    contract_info = mapper.get_by_bytecode("bytecodeA")
    assert contract_info is not None
    assert contract_info.bytecode == "bytecodeA"


def test_get_by_bytecode_nonexistent(mapper):
    contract_info = mapper.get_by_bytecode("bytecodeA")
    assert contract_info is None


def test_append_node(mapper, ast_nodes):
    mapper.add("ContractA", "bytecodeA", ast_nodes)
    new_node = AstNode(
        node_type="type3", id=3, name="Node3", address="0x789", visibility="public"
    )
    mapper.append_node("ContractA", new_node)
    contract_info = mapper.get_by_name("ContractA")
    assert contract_info is not None
    assert len(contract_info.nodes) == 3
    assert contract_info.nodes[-1].id == 3


def test_append_node_to_never_seen_before_contract(mapper):
    new_node = AstNode(
        node_type="type3", id=3, name="Node3", address="0x789", visibility="public"
    )

    mapper.append_node("NeverSeenBefore", new_node)
    assert mapper.get_by_name("NeverSeenBefore").nodes == [new_node]


def test_parse_simple_ast(mapper):
    example_ast = {
        "nodeType": "ContractDefinition",
        "id": 1,
        "name": "ExampleContract",
        "nodes": [
            {
                "nodeType": "FunctionDefinition",
                "id": 2,
                "name": "exampleFunction",
                "functionSelector": "abcdef",
                "visibility": "public",
                "nodes": [],
            }
        ],
    }

    mapper.parse_ast(example_ast)
    contract_info = mapper.get_by_name("ExampleContract")

    assert contract_info is not None
    assert contract_info.contract_name == "ExampleContract"
    assert len(contract_info.nodes) == 1
    assert contract_info.nodes[0].name == "exampleFunction"


def test_parse_complex_ast(mapper):
    complex_ast = {
        "nodeType": "ContractDefinition",
        "id": 1,
        "name": "ComplexContract",
        "nodes": [
            {
                "nodeType": "VariableDeclaration",
                "id": 2,
                "name": "var1",
                "functionSelector": "",
                "visibility": "private",
            },
            {
                "nodeType": "FunctionDefinition",
                "id": 3,
                "name": "func1",
                "functionSelector": "222222",
                "visibility": "public",
                "nodes": [
                    {
                        "nodeType": "Block",
                        "id": 4,
                        "name": "innerBlock",
                        "functionSelector": "",
                        "visibility": "",
                    }
                ],
            },
            {
                "nodeType": "EventDefinition",
                "id": 5,
                "name": "event1",
                "eventSelector": "444444",
                "visibility": "public",
            },
            {
                "nodeType": "ErrorDefinition",
                "id": 6,
                "name": "error1",
                "errorSelector": "555555",
                "visibility": "public",
            },
        ],
    }
    mapper.parse_ast(complex_ast)
    contract_info = mapper.get_by_name("ComplexContract")
    assert contract_info is not None
    assert contract_info.contract_name == "ComplexContract"

    assert len(contract_info.nodes) == 3

    node_names = [node.name for node in contract_info.nodes]
    assert "var1" not in node_names  # var1 is not added, it has no selector
    assert "func1" in node_names
    assert "event1" in node_names
    assert "error1" in node_names
