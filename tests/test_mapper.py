from typing import List

import json
import os
import pytest

from halmos.mapper import AstNode, Mapper, SingletonMeta


@pytest.fixture
def read_json_file(request):
    """fixture to read json files under tests/data"""

    def _read_file(filename):
        # Get the directory of the current test file
        test_dir = request.fspath.dirname
        file_path = os.path.join(test_dir, "data", filename)
        with open(file_path, "r") as file:
            return json.load(file)

    return _read_file


@pytest.fixture
def ast_nodes() -> List[AstNode]:
    return [
        AstNode(
            node_type="type1",
            name="Node1",
            selector="0x1234",
        ),
        AstNode(
            node_type="type2",
            name="Node2",
            selector="0x5678",
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
    new_node = AstNode(node_type="type3", name="Node3", selector="0x789")
    mapper.append_node("ContractA", new_node)
    contract_info = mapper.get_by_name("ContractA")
    assert contract_info is not None
    assert len(contract_info.nodes) == 3
    assert contract_info.nodes[-1].name == "Node3"


def test_append_node_to_never_seen_before_contract(mapper):
    new_node = AstNode(node_type="type3", name="Node3", selector="0x789")

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


def test_parse_multicontract_ast(read_json_file, mapper):
    json_data = read_json_file("multi-contract-ast.json")
    mapper.parse_ast(json_data["ast"])

    # the following are not in contract scope:
    #
    #   event Log(uint256);
    #   error Unauthorized();
    #   function someFreeFunc() pure returns (uint256) {
    #       return 42;
    #   }
    #
    # but the free function is not added to the mapper (it has no selector)
    not_in_contract = mapper.get_by_name(None)
    assert len(not_in_contract.nodes) == 2
    assert not_in_contract.nodes[0].name == "Log"
    assert (
        not_in_contract.nodes[0].selector
        == "0x909c57d5c6ac08245cf2a6de3900e2b868513fa59099b92b27d8db823d92df9c"
    )
    assert not_in_contract.nodes[1].name == "Unauthorized"
    assert not_in_contract.nodes[1].selector == "0x82b42900"
    assert mapper.lookup_selector("0x82b42900") == "Unauthorized"

    # there are 2 contracts in the AST
    # this would be visible as:
    # - out/TestA.sol/TestA.json (AST includes both TestA and C)
    # - out/TestA.sol/C.json (AST includes both TestA and C)

    # 3 total scopes, including the non-contract scope
    assert len(mapper._contracts) == 3

    # contract TestA {
    #    function internal_func() internal pure {}
    #    function test_foo() public view returns (uint256) { ... }
    # }
    #
    # the internal function is not added to the mapper (it has no selector)
    contract_TestA = mapper.get_by_name("TestA")
    assert contract_TestA is not None
    assert len(contract_TestA.nodes) == 1
    assert contract_TestA.nodes[0].name == "test_foo"
    assert contract_TestA.nodes[0].selector == "0xdc24e7f1"
    assert mapper.lookup_selector("0xdc24e7f1", contract_name="TestA") == "test_foo"

    # contract C {
    #     function foo() public pure returns (uint256) { ... }
    # }
    contract_C = mapper.get_by_name("C")
    assert contract_C is not None
    assert len(contract_C.nodes) == 1
    assert contract_C.nodes[0].name == "foo"
    assert contract_C.nodes[0].selector == "0xc2985578"
