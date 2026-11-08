from dolmos.solve import parse_model_str

# a model saved in an smt file (halmos#449): equalities instead of define-fun
EQ_MODEL = """sat
(=
 call_exit_code_6f14f2a_01
 #b0001)
(=
 p_i_uint128_3c00c77_00
 #b10000000)
(= p_n_uint128_9c1a26a_00 #x0400)
(= |p_y_address_1234567_01| (_ bv42 160))
(= storage_0x7fa9_256_00 @fun_6)
(function @fun_6
 (type (Array (_ BitVec 256) (_ BitVec 256)))
 (default #b0))
"""


def test_parse_model_with_equalities():
    model = parse_model_str(EQ_MODEL)
    assert sorted(model) == [
        "p_i_uint128_3c00c77_00",
        "p_n_uint128_9c1a26a_00",
        "p_y_address_1234567_01",
    ]
    assert model["p_i_uint128_3c00c77_00"].value == 0x80
    assert model["p_i_uint128_3c00c77_00"].size_bits == 8
    assert model["p_n_uint128_9c1a26a_00"].value == 0x400
    assert model["p_n_uint128_9c1a26a_00"].size_bits == 16
    assert model["p_y_address_1234567_01"].value == 42
    assert model["p_y_address_1234567_01"].size_bits == 160
    assert model["p_y_address_1234567_01"].solidity_type == "address"


def test_parse_model_define_fun_still_works():
    model = parse_model_str(
        "sat\n(model\n  (define-fun p_x_uint256_8d8a5a6_00 () (_ BitVec 256) #x01)\n)\n"
    )
    assert model["p_x_uint256_8d8a5a6_00"].value == 1
