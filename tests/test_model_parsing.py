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


# symbolic storage in counterexamples (halmos#577)

YICES_STORAGE_MODEL = """sat
(model
  (define-fun p_a_address_b175639_00 () (_ BitVec 256) (_ bv0 256))
  (define-fun storage_0xcccc0000_0_0_0_00 () (_ BitVec 256) (_ bv5 256))
  (define-fun storage_0xcccc0000_0_0_0_3f2a1b0_01 () (_ BitVec 256) (_ bv6 256))
  (define-fun
    storage_0xcccc0000_2_2_512_00
    ((x!0 (_ BitVec 512)))
    (_ BitVec 256)
    (ite (= x!0 (_ bv4660 512)) (_ bv77 256)
         (_ bv1503905229234623288492223863442734922411 256)))
  (define-fun storage_0xcccc0000_3_2_512_00 ((x!0 (_ BitVec 512))) (_ BitVec 256) (_ bv9 256))
  (define-fun storage_0xaaaa0000_160_00 ((x!0 (_ BitVec 160))) (_ BitVec 256)
    (ite (= x!0 #x0000000000000000000000000000000000000001) #x0000000000000000000000000000000000000000000000000000000000000002
    (ite (= x!0 #x0000000000000000000000000000000000000003) #x0000000000000000000000000000000000000000000000000000000000000004
      #x0000000000000000000000000000000000000000000000000000000000000000)))
  (define-fun f_sha3_512 ((x!0 (_ BitVec 512))) (_ BitVec 256)
    (ite (= x!0 (_ bv2 512)) (_ bv7788 256) (_ bv184 256))))
"""

Z3_STORAGE_MODEL = """sat
(
  (define-fun storage_0xcccc0000_2_2_512_00 () (Array (_ BitVec 512) (_ BitVec 256))
    (store (store ((as const (Array (_ BitVec 512) (_ BitVec 256)))
                   #x00000000000000000000000000000000000000000000000000000000000000ff)
             #x00000000000000000000000000000000000000000000000000000000000012340000000000000000000000000000000000000000000000000000000000000000
             #x000000000000000000000000000000000000000000000000000000000000004d)
      (_ bv2 512)
      (_ bv9 256)))
  (define-fun storage_0xcccc0000_3_2_512_00 () (Array (_ BitVec 512) (_ BitVec 256))
    ((as const (Array (_ BitVec 512) (_ BitVec 256)))
     #x00000000000000000000000000000000000000000000000000000000000000ee))
  (define-fun storage_0xcccc0000_4_2_512_00 () (Array (_ BitVec 512) (_ BitVec 256))
    ((as const (Array (_ BitVec 512) (_ BitVec 256)))
     #x0000000000000000000000000000000000000000000000000000000000000000))
  (define-fun balance_00 () (Array (_ BitVec 160) (_ BitVec 256))
    ((as const (Array (_ BitVec 160) (_ BitVec 256))) #x0000000000000000000000000000000000000000000000000000000000000007))
)
"""

EQ_STORAGE_MODEL = """sat
(= storage_0xcccc0000_0_0_0_00 #b0101)
(= storage_0x7fa9_256_00 @fun_6)
(function @fun_6
 (type (-> (bitvector 256) (bitvector 256)))
 (= (@fun_6 #b0111) #b0011)
 (default #b0000))
(function @fun_7
 (type (-> (bitvector 256) (bitvector 256)))
 (= (@fun_7 #b0001) #b0010)
 (default #b0000))
"""


def values(model):
    return {name: v.value for name, v in model.items()}


def test_parse_symbolic_storage_functions():
    model = parse_model_str(YICES_STORAGE_MODEL)
    assert values(model) == {
        "p_a_address_b175639_00": 0,
        # a scalar slot
        "storage_0xcccc0000_0_0_0_00": 5,
        # a mapping: the explicit entry, with one [word] per 256-bit key, and not the
        # arbitrary value of the other entries
        "storage_0xcccc0000_2_2_512_00[0x00][0x1234]": 77,
        # a mapping without explicit entries: the value of all the entries
        "storage_0xcccc0000_3_2_512_00[...]": 9,
        # generic storage layout: the key is the slot
        "storage_0xaaaa0000_160_00[0x01]": 2,
        "storage_0xaaaa0000_160_00[0x03]": 4,
    }

    # the intermediate states of the storage are not reported
    assert "storage_0xcccc0000_0_0_0_3f2a1b0_01" not in model

    scalar = model["storage_0xcccc0000_0_0_0_00"]
    assert (scalar.size_bits, scalar.solidity_type) == (256, "uint256")
    assert scalar.variable_name == scalar.full_name


def test_parse_symbolic_storage_arrays():
    assert values(parse_model_str(Z3_STORAGE_MODEL)) == {
        "storage_0xcccc0000_2_2_512_00[0x1234][0x00]": 0x4D,
        "storage_0xcccc0000_2_2_512_00[0x00][0x02]": 9,
        "storage_0xcccc0000_3_2_512_00[...]": 0xEE,
        # a zero default is the empty storage: not reported
    }


def test_parse_symbolic_storage_equalities():
    assert values(parse_model_str(EQ_STORAGE_MODEL)) == {
        "storage_0xcccc0000_0_0_0_00": 5,
        "storage_0x7fa9_256_00[0x07]": 3,
    }


def test_keep_storage_of_symbolic_accounts_only():
    from dolmos.solve import PotentialModel

    model = PotentialModel(model=parse_model_str(YICES_STORAGE_MODEL), is_valid=True)
    model.keep_storage_of(("storage_0xaaaa0000_",))
    assert sorted(model.model) == [
        "p_a_address_b175639_00",
        "storage_0xaaaa0000_160_00[0x01]",
        "storage_0xaaaa0000_160_00[0x03]",
    ]

    model.keep_storage_of(())
    assert sorted(model.model) == ["p_a_address_b175639_00"]


def test_render_notes_after_values():
    from dolmos.solve import PotentialModel

    # halmos#374: the function chosen by svm.createCalldata is printed after the values
    note = "svm.createCalldata: Token.burn(uint256) [selector 0x42966c68]"
    model = PotentialModel(
        model=parse_model_str(
            "(define-fun p_amount_uint256_54cf1f6_03 () (_ BitVec 256) #x40)"
        ),
        is_valid=True,
    )
    assert model.render(notes=(note,)) == (
        f"\n    p_amount_uint256_54cf1f6_03 = 0x40\n    {note}"
    )

    # a function without argument has no value, but is still told
    empty = PotentialModel(model={}, is_valid=True)
    assert empty.render(notes=(note,)) == f"\n    {note}"
    assert empty.render() == "∅"
