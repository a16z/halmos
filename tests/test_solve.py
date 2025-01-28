import pytest

from halmos.solve import ModelVariable, parse_model_str


@pytest.mark.parametrize(
    "full_name",
    [
        "halmos_y_uint256_043cfd7_01",
        "p_y_uint256_043cfd7_01",
    ],
)
def test_smtlib_z3_bv_output(full_name):
    smtlib_str = f"""
        (define-fun {full_name} () (_ BitVec 256)
        #x0000000000000000000000000000000000000000000000000000000000000000)
    """
    model = parse_model_str(smtlib_str)

    assert model[full_name] == ModelVariable(
        full_name=full_name,
        variable_name="y",
        solidity_type="uint256",
        smt_type="BitVec 256",
        size_bits=256,
        value=0,
    )


# note that yices only produces output like this with --smt2-model-format
# otherwise we get something like (= x #b00000100)
@pytest.mark.parametrize(
    "full_name",
    [
        "halmos_z_uint256_cabf047_02",
        "p_z_uint256_cabf047_02",
    ],
)
def test_smtlib_yices_binary_output(full_name):
    smtlib_str = f"""
    (define-fun
        {full_name}
        ()
        (_ BitVec 256)
        #b1000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000)
    """
    model = parse_model_str(smtlib_str)
    assert model[full_name] == ModelVariable(
        full_name=full_name,
        variable_name="z",
        solidity_type="uint256",
        smt_type="BitVec 256",
        size_bits=256,
        value=1 << 255,
    )


@pytest.mark.parametrize(
    "full_name",
    [
        "halmos_z_uint256_11ce021_08",
        "p_z_uint256_11ce021_08",
    ],
)
def test_smtlib_yices_decimal_output(full_name):
    val = 57896044618658097711785492504343953926634992332820282019728792003956564819968
    smtlib_str = f"""
        (define-fun {full_name} () (_ BitVec 256) (_ bv{val} 256))
    """
    model = parse_model_str(smtlib_str)
    assert model[full_name] == ModelVariable(
        full_name=full_name,
        variable_name="z",
        solidity_type="uint256",
        smt_type="BitVec 256",
        size_bits=256,
        value=val,
    )


@pytest.mark.parametrize(
    "full_name",
    [
        "halmos_x_uint8_043cfd7_01",
        "p_x_uint8_043cfd7_01",
    ],
)
def test_smtlib_stp_output(full_name):
    # we should tolerate:
    # - the extra (model) command
    # - duplicate variable names
    # - the initial `sat` result
    # - the `|` around the variable name
    # - the space in `( define-fun ...)`
    smtlib_str = f"""
        sat
        (model
        ( define-fun |{full_name}| () (_ BitVec 8) #x04 )
        )
        (model
        ( define-fun |{full_name}| () (_ BitVec 8) #x04 )
        )
    """
    model = parse_model_str(smtlib_str)
    assert model[full_name] == ModelVariable(
        full_name=full_name,
        variable_name="x",
        solidity_type="uint8",
        smt_type="BitVec 8",
        size_bits=8,
        value=4,
    )
