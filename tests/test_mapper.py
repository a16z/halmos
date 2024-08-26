import json
import os

import pytest

from halmos.mapper import AstNode, ContractMappingInfo, Mapper, SingletonMeta


@pytest.fixture
def read_json_file(request):
    """fixture to read json files under tests/data"""

    def _read_file(filename):
        # Get the directory of the current test file
        test_dir = request.fspath.dirname
        file_path = os.path.join(test_dir, "data", filename)
        with open(file_path) as file:
            return json.load(file)

    return _read_file


@pytest.fixture
def ast_nodes() -> list[AstNode]:
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
def mapping(ast_nodes) -> ContractMappingInfo:
    return ContractMappingInfo("ContractA", "bytecodeA").with_nodes(ast_nodes)


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


def test_add_mapping(mapper, mapping):
    mapper.add_mapping(mapping)
    contract_info = mapper.get_by_name("ContractA")
    assert contract_info is not None
    assert contract_info.contract_name == "ContractA"
    assert contract_info.bytecode == "bytecodeA"
    assert len(contract_info.nodes) == 2


def test_add_mapping_already_exists(mapper, mapping):
    mapper.add_mapping(mapping)
    with pytest.raises(ValueError, match=r"Contract ContractA already exists"):
        mapper.add_mapping(mapping)


def test_get_by_name(mapper):
    mapper.get_or_create("ContractA")
    contract_info = mapper.get_by_name("ContractA")
    assert contract_info is not None
    assert contract_info.contract_name == "ContractA"


def test_get_by_name_nonexistent(mapper):
    contract_info = mapper.get_by_name("ContractA")
    assert contract_info is None


def test_get_by_bytecode(mapper, mapping):
    mapper.add_mapping(mapping)
    contract_info = mapper.get_by_bytecode("bytecodeA")
    assert contract_info is not None
    assert contract_info.bytecode == "bytecodeA"


def test_get_by_bytecode_nonexistent(mapper):
    contract_info = mapper.get_by_bytecode("bytecodeA")
    assert contract_info is None


def test_add_node(mapper, mapping):
    mapper.add_mapping(mapping)

    # when we add a new node to a contract scope
    new_node = AstNode(node_type="type3", name="Node3", selector="0x789")
    mapper.add_node(mapping.contract_name, new_node)

    # then we can retrieve it from the contract scope
    contract_info = mapper.get_by_name(mapping.contract_name)
    assert contract_info is not None
    assert len(contract_info.nodes) == 3
    assert contract_info.nodes[new_node.selector].name == "Node3"


def test_add_node_to_never_seen_before_contract(mapper):
    new_node = AstNode(node_type="type3", name="Node3", selector="0x789")

    mapper.add_node("NeverSeenBefore", new_node)
    assert mapper.get_by_name("NeverSeenBefore").nodes == {new_node.selector: new_node}


def test_lookup_selector(mapper, ast_nodes):
    # when we look up an unknown selector, we should get the selector back
    assert mapper.lookup_selector("0x1234") == "0x1234"

    # when we add a new node to a contract scope
    node1 = ast_nodes[0]
    selector = node1.selector
    mapper.add_node("ContractA", node1)

    # then we can look up the selector by specifying the contract name
    assert mapper.lookup_selector(selector, contract_name="ContractA") == node1.name

    # and we can look up the selector without specifying the contract scope
    assert mapper.lookup_selector(selector) == node1.name

    # when we add another node with the same selector
    node2 = AstNode(
        node_type=node1.node_type, name="ConflictingNode", selector=selector
    )

    mapper.add_node("ContractB", node2)

    # then we can look up the selector by specifying the contract scope
    assert mapper.lookup_selector(selector, contract_name="ContractA") == node1.name
    assert mapper.lookup_selector(selector, contract_name="ContractB") == node2.name

    # if we look up without specifying the scope, we could get either name
    assert mapper.lookup_selector(selector) in [node1.name, node2.name]


def test_lookup_selector_unscoped(mapper, ast_nodes):
    # when we add a new node with no contract scope (e.g. global errors or events)
    node1 = ast_nodes[0]
    selector = node1.selector
    mapper.add_node(None, node1)

    # then we can look up the selector even if we specify a contract scope
    assert mapper.lookup_selector(selector, contract_name="ContractA") == node1.name

    # and we can look up the selector without specifying the contract scope
    assert mapper.lookup_selector(selector) == node1.name


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
    assert next(iter(contract_info.nodes.values())).name == "exampleFunction"


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

    node_names = [node.name for node in contract_info.nodes.values()]
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
    nodes = iter(not_in_contract.nodes.values())
    first_node = next(nodes)
    assert first_node.name == "Log"
    assert (
        first_node.selector
        == "0x909c57d5c6ac08245cf2a6de3900e2b868513fa59099b92b27d8db823d92df9c"
    )
    second_node = next(nodes)
    assert second_node.name == "Unauthorized"
    assert second_node.selector == "0x82b42900"
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
    node = next(iter(contract_TestA.nodes.values()))
    assert node.name == "test_foo"
    assert node.selector == "0xdc24e7f1"
    assert mapper.lookup_selector("0xdc24e7f1", contract_name="TestA") == "test_foo"

    # contract C {
    #     function foo() public pure returns (uint256) { ... }
    # }
    contract_C = mapper.get_by_name("C")
    assert contract_C is not None
    assert len(contract_C.nodes) == 1
    node = next(iter(contract_C.nodes.values()))
    assert node.name == "foo"
    assert node.selector == "0xc2985578"
