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


def test_add_contract_mapping_info(mapper, ast_nodes):
    mapper.add_contract_mapping_info("ContractA", "bytecodeA", ast_nodes)
    contract_info = mapper.get_contract_mapping_info_by_name("ContractA")
    assert contract_info is not None
    assert contract_info.contract_name == "ContractA"
    assert contract_info.bytecode == "bytecodeA"
    assert len(contract_info.nodes) == 2


def test_add_contract_mapping_info_already_existence(mapper, ast_nodes):
    mapper.add_contract_mapping_info("ContractA", "bytecodeA", ast_nodes)

    with pytest.raises(ValueError, match=r"Contract ContractA already exists"):
        mapper.add_contract_mapping_info("ContractA", "bytecodeA", ast_nodes)


def test_get_contract_mapping_info_by_name(mapper, ast_nodes):
    mapper.add_contract_mapping_info("ContractA", "bytecodeA", ast_nodes)
    contract_info = mapper.get_contract_mapping_info_by_name("ContractA")
    assert contract_info is not None
    assert contract_info.contract_name == "ContractA"


def test_get_contract_mapping_info_by_name_nonexistent(mapper):
    contract_info = mapper.get_contract_mapping_info_by_name("ContractA")
    assert contract_info is None


def test_get_contract_mapping_info_by_bytecode(mapper, ast_nodes):
    mapper.add_contract_mapping_info("ContractA", "bytecodeA", ast_nodes)
    contract_info = mapper.get_contarct_mapping_info_by_bytecode("bytecodeA")
    assert contract_info is not None
    assert contract_info.bytecode == "bytecodeA"


def test_get_contract_mapping_info_by_bytecode_nonexistent(mapper):
    contract_info = mapper.get_contarct_mapping_info_by_bytecode("bytecodeA")
    assert contract_info is None


def test_append_node(mapper, ast_nodes):
    mapper.add_contract_mapping_info("ContractA", "bytecodeA", ast_nodes)
    new_node = AstNode(
        node_type="type3", id=3, name="Node3", address="0x789", visibility="public"
    )
    mapper.append_node("ContractA", new_node)
    contract_info = mapper.get_contract_mapping_info_by_name("ContractA")
    assert contract_info is not None
    assert len(contract_info.nodes) == 3
    assert contract_info.nodes[-1].id == 3


def test_append_node_to_nonexistent_contract(mapper):
    new_node = AstNode(
        node_type="type3", id=3, name="Node3", address="0x789", visibility="public"
    )
    with pytest.raises(ValueError, match=r"Contract NonexistentContract not found"):
        mapper.append_node("NonexistentContract", new_node)
