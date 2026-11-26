"""Tests of --pretty-counterexamples (dolmos.pcex) and of the EXP refinement (dolmos.solve)"""

import json
import os
import shlex
import shutil
import sys
from dataclasses import replace
from pathlib import Path

import pytest
from z3 import BitVec, BitVecSort, BitVecVal, Function, Solver, sat

from dolmos.config import ConfigSource, default_config
from dolmos.pcex import (
    EMPTY_SELECTOR,
    AbiType,
    CallLayout,
    CexLayout,
    CodeGen,
    ModelReader,
    PcexState,
    Ref,
    RenderContext,
    Segment,
    SelectorIndex,
    TraceCall,
    abi_decode,
    abi_encode,
    base_literal,
    bytes_literal,
    checksum_address,
    compact_hex,
    index_symbols,
    params_type,
    parse_abi_type,
    render_counterexample,
    repro_function,
    segments_of,
    selector_of,
    svm_value,
    uint_hint,
)
from dolmos.solve import (
    ExpApp,
    ExpApps,
    ModelVariable,
    PathContext,
    SMTQuery,
    SolvingContext,
    exp_arg_decls,
    exp_invalid_reason,
    exp_square_and_multiply,
    exp_table,
    mk_exp_apps,
    parse_exp_arg_values,
    solve_end_to_end,
)

#
# helpers
#


def var(name: str, value: int, size: int = 256) -> ModelVariable:
    return ModelVariable(
        full_name=name,
        variable_name="",
        solidity_type="",
        smt_type=f"BitVec {size}",
        size_bits=size,
        value=value,
    )


def model_of(*variables: ModelVariable) -> dict:
    return {v.full_name: v for v in variables}


def word(value: int) -> bytes:
    return value.to_bytes(32, "big")


TOKEN_ABI = [
    {
        "type": "function",
        "name": "transfer",
        "inputs": [
            {"name": "to", "type": "address", "internalType": "address"},
            {"name": "amount", "type": "uint256", "internalType": "uint256"},
        ],
        "outputs": [{"name": "", "type": "bool", "internalType": "bool"}],
        "stateMutability": "nonpayable",
    },
    {
        "type": "function",
        "name": "withdraw",
        "inputs": [{"name": "amount", "type": "uint256", "internalType": "uint256"}],
        "outputs": [],
        "stateMutability": "nonpayable",
    },
    {"type": "receive", "stateMutability": "payable"},
]

TOKEN_JSON = {"abi": TOKEN_ABI, "deployedBytecode": {"object": "0x6080"}}


def token_index() -> SelectorIndex:
    return SelectorIndex([("Token", TOKEN_JSON)])


#
# symbol names
#


def test_index_symbols():
    names = [
        "p_x_uint256_0a1b2c3_00",
        "p_my_var_bytes32_abcdef0_01",
        "p_calls[0]_bytes_1234567_00",
        "p_calls[0]_length_7654321_00",
        "p_calls_length_aaaaaaa_00",
        "p_s.items[1].a_int8_bbbbbbb_12",
        "p__uint256_ccccccc_00",
        "p__uint256_ddddddd_00",
        "dolmos_x_uint256_eeeeeee_01",
    ]
    index = index_symbols(names)
    assert index[("x", "uint256")] == ["p_x_uint256_0a1b2c3_00"]
    assert index[("my_var", "bytes32")] == ["p_my_var_bytes32_abcdef0_01"]
    assert index[("calls[0]", "bytes")] == ["p_calls[0]_bytes_1234567_00"]
    assert index[("calls[0]", "length")] == ["p_calls[0]_length_7654321_00"]
    assert index[("calls", "length")] == ["p_calls_length_aaaaaaa_00"]
    assert index[("s.items[1].a", "int8")] == ["p_s.items[1].a_int8_bbbbbbb_12"]
    # unnamed parameters share the same path, in order
    assert index[("", "uint256")] == ["p__uint256_ccccccc_00", "p__uint256_ddddddd_00"]
    assert len(index) == 7


#
# ABI types, encoding and decoding
#


def test_parse_abi_type():
    t = parse_abi_type(
        {
            "name": "ps",
            "type": "tuple[2][]",
            "internalType": "struct Foo.Pair[2][]",
            "components": [
                {"name": "a", "type": "uint", "internalType": "uint256"},
                {"name": "b", "type": "bytes4[]", "internalType": "bytes4[]"},
            ],
        }
    )
    assert t.kind == "array"
    assert t.abi == "(uint256,bytes4[])[2][]"
    assert t.internal == "struct Foo.Pair[2][]"
    assert t.elem.kind == "fixed" and t.elem.length == 2
    assert t.elem.internal == "struct Foo.Pair[2]"
    pair = t.elem.elem
    assert pair.kind == "tuple" and pair.names == ("a", "b")
    assert pair.internal == "struct Foo.Pair"
    assert pair.components[0].abi == "uint256"
    assert pair.is_dynamic and t.is_dynamic

    static = parse_abi_type(
        {
            "type": "tuple",
            "components": [
                {"name": "x", "type": "uint8"},
                {"name": "y", "type": "address[3]"},
            ],
        }
    )
    assert not static.is_dynamic
    assert static.static_size == 4 * 32


# examples from the solidity documentation (ABI specification)
DOC_F = (
    "8be65246"
    "0000000000000000000000000000000000000000000000000000000000000123"
    "0000000000000000000000000000000000000000000000000000000000000080"
    "3132333435363738393000000000000000000000000000000000000000000000"
    "00000000000000000000000000000000000000000000000000000000000000e0"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000456"
    "0000000000000000000000000000000000000000000000000000000000000789"
    "000000000000000000000000000000000000000000000000000000000000000d"
    "48656c6c6f2c20776f726c642100000000000000000000000000000000000000"
)

DOC_G = (
    "2289b18c"
    "0000000000000000000000000000000000000000000000000000000000000040"
    "0000000000000000000000000000000000000000000000000000000000000140"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000040"
    "00000000000000000000000000000000000000000000000000000000000000a0"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000001"
    "0000000000000000000000000000000000000000000000000000000000000002"
    "0000000000000000000000000000000000000000000000000000000000000001"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "0000000000000000000000000000000000000000000000000000000000000060"
    "00000000000000000000000000000000000000000000000000000000000000a0"
    "00000000000000000000000000000000000000000000000000000000000000e0"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "6f6e650000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000003"
    "74776f0000000000000000000000000000000000000000000000000000000000"
    "0000000000000000000000000000000000000000000000000000000000000005"
    "7468726565000000000000000000000000000000000000000000000000000000"
)


def test_abi_decode_encode_doc_example_f():
    data = bytes.fromhex(DOC_F)
    assert selector_of("f(uint256,uint32[],bytes10,bytes)") == data[:4]

    params = params_type(
        [
            {"name": "a", "type": "uint256"},
            {"name": "b", "type": "uint32[]"},
            {"name": "c", "type": "bytes10"},
            {"name": "d", "type": "bytes"},
        ]
    )
    v = abi_decode(params, data, 4)
    a, b, c, d = v.items
    assert a.word == 0x123
    assert [item.word for item in b.items] == [0x456, 0x789]
    assert c.word.to_bytes(32, "big")[:10] == b"1234567890"
    assert d.data == b"Hello, world!"
    assert abi_encode(v) == data[4:]


def test_abi_decode_encode_doc_example_g():
    data = bytes.fromhex(DOC_G)
    assert selector_of("g(uint256[][],string[])") == data[:4]

    params = params_type(
        [{"name": "x", "type": "uint256[][]"}, {"name": "y", "type": "string[]"}]
    )
    v = abi_decode(params, data, 4)
    x, y = v.items
    assert [[i.word for i in row.items] for row in x.items] == [[1, 2], [3]]
    assert [s.data for s in y.items] == [b"one", b"two", b"three"]
    assert abi_encode(v) == data[4:]


@pytest.mark.parametrize(
    "data",
    [
        word(0x20),  # offset without length
        word(0x20) + word(2**200),  # absurd length
        word(2**100),  # offset out of bounds
    ],
)
def test_abi_decode_malformed(data):
    from dolmos.pcex import AbiDecodeError

    with pytest.raises(AbiDecodeError):
        abi_decode(params_type([{"name": "b", "type": "bytes"}]), data)


#
# values from the model
#


def test_model_reader_dynamic_lengths():
    # check_calls(bytes[] calls) with calls.length == 2, calls[1].length == 65
    params = params_type([{"name": "calls", "type": "bytes[]"}])
    calldata = bytes.fromhex("a9059cbb") + word(0xBEEF) + word(5) + b"\x07"
    model = model_of(
        var("p_calls_length_aaaaaaa_00", 2),
        var("p_calls[0]_length_bbbbbbb_00", 0),
        var("p_calls[0]_bytes_ccccccc_00", 0, 8 * 1024),
        var("p_calls[1]_length_ddddddd_00", 69),
        var(
            "p_calls[1]_bytes_eeeeeee_00",
            int.from_bytes(calldata + bytes(1024 - 69), "big"),
            8 * 1024,
        ),
    )
    reader = ModelReader(model, index_symbols(model))
    v = reader.read(params, "")
    calls = v.items[0]
    assert [item.data for item in calls.items] == [b"", calldata]
    assert reader.used == set(model)

    ctx = RenderContext(index=token_index())
    leaves = dict(ctx.leaves("calls", calls))
    assert leaves["calls.length"] == "2"
    assert leaves["calls[0]"] == "0x (empty)"
    decoded, raw = leaves["calls[1]"].split("\n")
    assert decoded == (
        "Token.transfer(to: 0x000000000000000000000000000000000000bEEF, amount: 5)"
        " + 1 trailing bytes"
    )
    assert raw.endswith("(69 bytes)")


def test_model_reader_missing_symbols_are_free():
    params = params_type(
        [{"name": "x", "type": "uint256"}, {"name": "s", "type": "string"}]
    )
    reader = ModelReader(
        {}, index_symbols(["p_x_uint256_aaaaaaa_00", "p_s_length_bbbbbbb_00"])
    )
    v = reader.read(params, "")
    assert v.items[0].free and v.items[0].word == 0
    assert v.items[1].free and v.items[1].data == b""
    assert RenderContext().leaves("x", v.items[0]) == [("x", "0 (any value)")]


def test_svm_value():
    t, w, _ = svm_value(var("dolmos_d_int16_aaaaaaa_01", 0xFFFE, 16), "int16")
    assert RenderContext().render_base(t, w) == "-2"

    t, w, _ = svm_value(var("dolmos_s_bytes4_aaaaaaa_01", 0x2E1A7D4D, 32), "bytes4")
    assert RenderContext(index=token_index()).render_base(t, w) == (
        "0x2e1a7d4d (Token.withdraw(uint256))"
    )

    t, _, data = svm_value(var("dolmos_b_bytes_aaaaaaa_01", 0xABCD, 16), "bytes")
    assert t.kind == "bytes" and data == b"\xab\xcd"


#
# rendering
#


def test_empty_selector_is_explained():
    # halmos#419: 0x00000000 is rendered as the selector of plain ether transfers
    ctx = RenderContext(index=token_index())
    t = AbiType("base", "bytes4")
    rendered = ctx.render_base(t, 0)
    assert rendered.startswith("0x00000000 (no selector: empty calldata")
    assert "receive()" in rendered

    # unless some contract has a function with that selector
    index = SelectorIndex(
        [
            (
                "Vanity",
                {
                    "abi": [
                        {
                            "type": "function",
                            "name": "wycpnbqcyf",
                            "inputs": [],
                            "outputs": [],
                            "stateMutability": "nonpayable",
                        }
                    ]
                },
            )
        ]
    )
    assert selector_of("wycpnbqcyf()") == EMPTY_SELECTOR
    assert (
        RenderContext(index=index).render_base(t, 0)
        == "0x00000000 (Vanity.wycpnbqcyf())"
    )


@pytest.mark.parametrize(
    "address",
    [
        # EIP-55 test vectors
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ],
)
def test_checksum_address(address):
    assert checksum_address(int(address, 16)) == address


@pytest.mark.parametrize(
    "value, bits, hint",
    [
        (2**256 - 1, 256, "type(uint256).max"),
        (2**256 - 3, 256, "type(uint256).max - 2"),
        (2**255, 256, "2**255"),
        (10**18, 256, "1e18"),
        (15 * 10**17, 256, "1.5e18"),
        (6 * 2**64, 256, hex(6 * 2**64)),
        (42, 256, None),
        (255, 8, "type(uint8).max"),
    ],
)
def test_uint_hint(value, bits, hint):
    assert uint_hint(value, bits) == hint


def test_compact_hex():
    assert compact_hex(b"") == "0x"
    assert compact_hex(bytes(1024)) == "0x00…00 (1024 zero bytes)"
    assert compact_hex(b"\xab" + bytes(40)) == "0xab + 40 zero bytes"
    assert compact_hex(b"\xab" + bytes(3)) == "0xab000000"


def test_render_dirty_values():
    ctx = RenderContext()
    assert ctx.render_base(AbiType("base", "address"), 2**160).endswith(
        "(not a valid address)"
    )
    assert ctx.render_base(AbiType("base", "int8"), 2**256 - 128) == (
        "-128 (type(int8).min)"
    )
    assert ctx.render_base(AbiType("base", "int8"), 2**256 - 129).endswith(
        "(not a valid int8)"
    )


#
# duplicates (halmos#398)
#


def test_pcex_state_hides_duplicates():
    state = PcexState()
    assert state.admit("x = 0", is_valid=True)
    assert not state.admit("x = 0", is_valid=True)
    assert not state.admit("x = 0", is_valid=True)
    assert state.admit("x = 1", is_valid=False)
    assert not state.admit("x = 1", is_valid=False)
    # a valid counterexample is shown even if an invalid one had the same values
    assert state.admit("x = 1", is_valid=True)
    assert not state.admit("x = 1", is_valid=False)
    assert (state.shown, state.hidden) == (3, 4)


#
# reproduction
#


def test_base_literals():
    assert base_literal(AbiType("base", "uint8"), 42) == "42"
    assert base_literal(AbiType("base", "uint8"), 256) is None
    assert base_literal(AbiType("base", "uint256"), 2**200) == hex(2**200)
    assert base_literal(AbiType("base", "int8"), 2**256 - 128) == "type(int8).min"
    assert base_literal(AbiType("base", "int16"), 2**256 - 3) == "-3"
    assert base_literal(AbiType("base", "bool"), 1) == "true"
    assert base_literal(AbiType("base", "bool"), 2) is None
    assert (
        base_literal(AbiType("base", "bytes4"), 0x12345678 << 224)
        == "bytes4(0x12345678)"
    )
    assert base_literal(AbiType("base", "bytes4"), 1) is None
    assert base_literal(AbiType("base", "address"), 0) == "address(0)"
    assert (
        base_literal(AbiType("base", "address", internal="contract IERC20"), 0xBEEF)
        == "IERC20(payable(0x000000000000000000000000000000000000bEEF))"
    )
    assert (
        base_literal(AbiType("base", "uint8", internal="enum Foo.Kind"), 2)
        == "Foo.Kind(2)"
    )
    assert (
        base_literal(AbiType("base", "uint256", internal="Price"), 7) == "Price.wrap(7)"
    )


def test_bytes_literals():
    assert bytes_literal(b"") == '""'
    assert bytes_literal(b"\xab\xcd") == 'hex"abcd"'
    assert bytes_literal(bytes(100)) == "new bytes(100)"
    assert (
        bytes_literal(b"\xab" + bytes(100))
        == 'abi.encodePacked(hex"ab", new bytes(100))'
    )


def test_codegen_structs_and_arrays():
    params = params_type(
        [
            {
                "name": "ps",
                "type": "tuple[]",
                "internalType": "struct T.Pair[]",
                "components": [
                    {"name": "a", "type": "uint256", "internalType": "uint256"},
                    {"name": "b", "type": "int8", "internalType": "int8"},
                ],
            },
            {"name": "fixedArr", "type": "uint16[3]", "internalType": "uint16[3]"},
            {"name": "data", "type": "bytes", "internalType": "bytes"},
        ]
    )
    data = abi_encode_args(params, [[(0, 0), (7, -3)], [0, 0, 9], b"\x01"])
    v = abi_decode(params, data)

    gen = CodeGen()
    args = gen.args(params, v)
    assert gen.ok
    assert args == ["ps", "fixedArr", 'hex"01"']
    assert gen.lines == [
        "T.Pair[] memory ps = new T.Pair[](2);",
        "ps[1].a = 7;",
        "ps[1].b = -3;",
        "uint16[3] memory fixedArr;",
        "fixedArr[2] = 9;",
    ]


def test_codegen_rejects_dirty_values():
    params = params_type([{"name": "x", "type": "uint8", "internalType": "uint8"}])
    gen = CodeGen()
    gen.args(params, abi_decode(params, word(300)))
    assert not gen.ok


def abi_encode_args(params: AbiType, values: list) -> bytes:
    """encodes python values with the dolmos.pcex encoder (test helper)"""
    from dolmos.pcex import Val

    def to_val(t, value):
        match t.kind:
            case "base":
                return Val(t, word=value % 2**256)
            case "bytes" | "string":
                return Val(t, data=value)
            case "array" | "fixed":
                return Val(t, items=[to_val(t.elem, x) for x in value])
            case _:
                return Val(
                    t,
                    items=[
                        to_val(c, x) for c, x in zip(t.components, value, strict=True)
                    ],
                )

    return abi_encode(to_val(params, values))


def mk_call(fun_name, sig, inputs, symbols, target=None, contract=None, **refs):
    return CallLayout(
        contract=contract,
        fun_name=fun_name,
        fun_sig=sig,
        inputs_json=json.dumps(inputs),
        payable=False,
        target=target,
        sender=refs.get("sender", Ref()),
        origin=refs.get("origin", Ref()),
        value=refs.get("value", Ref(const=0)),
        symbols=index_symbols(symbols),
    )


def test_render_counterexample_check_test():
    inputs = [{"name": "x", "type": "uint256", "internalType": "uint256"}]
    layout = CexLayout(
        test_contract="FooTest",
        test_source="test/Foo.t.sol",
        fun_name="check_x",
        fun_sig="check_x(uint256)",
        is_invariant=False,
        is_probe=False,
        test_call=mk_call(
            "check_x", "check_x(uint256)", inputs, ["p_x_uint256_aaaaaaa_00"]
        ),
        sequence=(),
        render_ctx=RenderContext(index=token_index()),
    )
    model = model_of(
        var("p_x_uint256_aaaaaaa_00", 10**18),
        var("dolmos_sel_bytes4_bbbbbbb_01", 0, 32),
        var("dolmos_n_uint8_ccccccc_02", 3, 8),
    )
    rendered = render_counterexample(layout, model)
    assert rendered.body == [
        "    x = 1000000000000000000 (1e18)",
        "    Other symbols:",
        "        n (uint8) = 3",
        "        sel (bytes4) = 0x00000000 (no selector: empty calldata, i.e. receive() or "
        "fallback(), e.g. a plain ether transfer)",
    ]
    function = repro_function(layout, rendered, 1)
    assert function[0].startswith("Reproduce: add to FooTest (test/Foo.t.sol)")
    assert function[1:] == [
        "    function test_pcex_check_x_1() public {",
        "        // values chosen for the symbols created by the test (replace the svm cheatcodes):",
        '        //   svm.createUint(8, "n") = 3',
        '        //   svm.createBytes4("sel") = 0x00000000 (no selector: empty calldata, i.e. '
        "receive() or fallback(), e.g. a plain ether transfer)",
        "        this.check_x(1000000000000000000);",
        "    }",
    ]


def test_render_counterexample_invariant_sequence():
    vault = 0xCCCC0000
    sender = 0xABCD
    inputs = [{"name": "amount", "type": "uint256", "internalType": "uint256"}]
    deposit = replace(
        mk_call(
            "deposit",
            "deposit(uint256)",
            inputs,
            ["p_amount_uint256_aaaaaaa_03"],
            target=vault,
            contract="Vault",
            sender=Ref(symbol="dolmos_msg_sender_0xcccc0000_bbbbbbb_01"),
            origin=Ref(symbol="dolmos_tx_origin_0xcccc0000_ccccccc_00"),
            value=Ref(symbol="dolmos_msg_value_0xcccc0000_ddddddd_02"),
        ),
        payable=True,
    )
    layout = CexLayout(
        test_contract="InvTest",
        test_source=None,
        fun_name="invariant_x",
        fun_sig="invariant_x()",
        is_invariant=True,
        is_probe=False,
        test_call=mk_call("invariant_x", "invariant_x()", [], []),
        sequence=(deposit, deposit),
        render_ctx=RenderContext(
            addr_names={vault: "Vault"},
            test_vars={vault: ("vault", "contract Vault")},
            index=SelectorIndex(),
        ),
    )
    model = model_of(
        var("p_amount_uint256_aaaaaaa_03", 5),
        var("dolmos_msg_sender_0xcccc0000_bbbbbbb_01", sender, 160),
        var("dolmos_tx_origin_0xcccc0000_ccccccc_00", sender, 160),
        var("dolmos_msg_value_0xcccc0000_ddddddd_02", 5),
        var("dolmos_block_timestamp_depth1_eeeeeee", 100, 64),
        var("dolmos_block_timestamp_depth2_fffffff", 200, 64),
    )
    rendered = render_counterexample(layout, model)
    sender_str = checksum_address(sender)
    assert rendered.body == [
        "    Sequence:",
        "        [1] Vault(vault).deposit(amount: 5)",
        f"            msg.sender: {sender_str}, msg.value: 5",
        "        [2] Vault(vault).deposit(amount: 5)",
        f"            msg.sender: {sender_str}, msg.value: 5, block.timestamp: 100",
        "        then invariant_x() at block.timestamp: 200",
    ]
    assert rendered.repro == [
        f"vm.deal({sender_str}, 5);",
        f"vm.prank({sender_str});",
        "vault.deposit{value: 5}(5);",
        "vm.warp(100);",
        f"vm.deal({sender_str}, 5);",
        f"vm.prank({sender_str});",
        "vault.deposit{value: 5}(5);",
        "vm.warp(200);",
        "this.invariant_x();",
    ]


def test_render_trace_calls():
    # calldata built by svm.createCalldata("Token"): selector + 2 symbolic words
    to, amount = "p_to_address_aaaaaaa_05", "p_amount_uint256_bbbbbbb_06"
    trace_call = TraceCall(
        target=0xCCCC0000,
        value=Ref(const=0),
        segments=(
            Segment(const=0xA9059CBB, size=32),
            Segment(symbol=to, size=256),
            Segment(symbol=amount, size=256),
        ),
    )
    layout = CexLayout(
        test_contract="T",
        test_source=None,
        fun_name="check_c",
        fun_sig="check_c()",
        is_invariant=False,
        is_probe=False,
        test_call=mk_call("check_c", "check_c()", [], []),
        sequence=(),
        render_ctx=RenderContext(
            addr_names={0xCCCC0000: "Token"},
            test_vars={0xCCCC0000: ("token", "contract Token")},
            index=token_index(),
        ),
        trace_calls=(trace_call,),
    )
    rendered = render_counterexample(layout, model_of(var(to, 0xBEEF), var(amount, 7)))
    assert rendered.body == [
        "    Calls made with symbolic calldata:",
        "        Token(token) ← Token.transfer("
        "to: 0x000000000000000000000000000000000000bEEF, amount: 7)",
    ]
    assert rendered.repro[1] == (
        "//   calldata sent to Token(token) = Token.transfer("
        "to: 0x000000000000000000000000000000000000bEEF, amount: 7), i.e. "
        'hex"a9059cbb000000000000000000000000000000000000000000000000000000000000beef'
        '0000000000000000000000000000000000000000000000000000000000000007"'
    )


def test_segments_of():
    x = BitVec("p_x_uint256_aaaaaaa_00", 256)
    b = BitVec("dolmos_b_bool_bbbbbbb_01", 1)
    from z3 import Concat, Extract, ZeroExt

    expr = Concat(BitVecVal(0x12345678, 32), Extract(255, 248, x), ZeroExt(255, b))
    segments = segments_of(expr)
    call = TraceCall(target=None, value=Ref(), segments=tuple(segments))
    model = model_of(
        var("p_x_uint256_aaaaaaa_00", 0xAB << 248),
        var("dolmos_b_bool_bbbbbbb_01", 1, 1),
    )
    assert call.calldata(model) == bytes.fromhex("12345678ab") + word(1)

    # anything else than constants, symbols, extracts and zero extensions is not evaluated
    assert segments_of(x + 1) is None


#
# EXP refinement (halmos#280)
#


def test_mk_exp_apps():
    f = Function("f_evm_exp_256", BitVecSort(256), BitVecSort(256), BitVecSort(256))
    x = BitVec("p_x_uint256_aaaaaaa_00", 256)
    y = BitVec("p_y_uint256_bbbbbbb_00", 256)
    three, ten = BitVecVal(3, 256), BitVecVal(10, 256)
    apps = mk_exp_apps([f(x, three) == 27, f(ten, y) > 5, f(x, three) != f(x, y)])
    assert apps.complete
    found = {(a.base_value, a.exponent_value) for a in apps.apps}
    assert found == {(None, 3), (10, None), (None, None)}
    assert len(apps) == 3


@pytest.mark.parametrize("base", [0, 1, 2, 3, 4, 10, 7, 2**255, 2**256 - 1])
@pytest.mark.parametrize("exponent", [0, 1, 2, 5, 64, 127, 128, 255, 256, 300])
def test_exp_table(base, exponent):
    from z3 import parse_smt2_string

    query = (
        "(declare-fun e () (_ BitVec 256))\n"
        "(declare-fun r () (_ BitVec 256))\n"
        f"(assert (= e (_ bv{exponent} 256)))\n"
        f"(assert (= r {exp_table(base, 'e', 'r')}))\n"
    )
    solver = Solver()
    solver.add(parse_smt2_string(query))
    assert solver.check() == sat
    r = solver.model().eval(BitVec("r", 256), model_completion=True).as_long()

    exact = base % 2 == 0 or base == 1 or exponent < 256
    if exact:
        assert r == pow(base, exponent, 2**256)


@pytest.mark.parametrize("exponent", [0, 1, 2, 3, 10, 255, 2**20 + 3])
def test_exp_square_and_multiply(exponent):
    from z3 import parse_smt2_string

    base = 0x123456789ABCDEF
    query = (
        "(declare-fun pcex_expb_0 () (_ BitVec 256))\n"
        "(declare-fun pcex_expr_0 () (_ BitVec 256))\n"
        f"(assert (= pcex_expb_0 (_ bv{base} 256)))\n"
        + exp_square_and_multiply(0, exponent)
    )
    solver = Solver()
    solver.add(parse_smt2_string(query))
    assert solver.check() == sat
    r = solver.model().eval(BitVec("pcex_expr_0", 256)).as_long()
    assert r == pow(base, exponent, 2**256)


def test_parse_exp_arg_values():
    stdout = """sat
    (define-fun pcex_expb_0 () (_ BitVec 256) (_ bv8 256))
    (define-fun pcex_expe_0 () (_ BitVec 256) #x0000000000000000000000000000000000000000000000000000000000000003)
    (define-fun |pcex_expr_0| () (_ BitVec 256) (_ bv27 256))
    (define-fun pcex_expb_1 () (_ BitVec 256) (_ bv2 256))
    """
    assert parse_exp_arg_values(stdout) == {0: {"b": 8, "e": 3, "r": 27}, 1: {"b": 2}}


def test_exp_invalid_reason():
    apps = ExpApps((ExpApp("p_x", "p_y"), ExpApp("#x0a", "p_y", base_value=10)))
    reason = exp_invalid_reason(apps, {0: {"b": 7, "e": 300, "r": 5}}, [0], [1])
    assert reason.startswith("EXP is approximated: ")
    assert "x ** y (symbolic base and exponent): the model takes 7 ** 300 = 5" in reason
    assert "10 ** y: the solver did not report its operands" in reason
    assert "vm.assume" in reason


def yices_command() -> list[str] | None:
    path = shutil.which("yices-smt2") or str(Path(sys.prefix) / "bin" / "yices-smt2")
    if not os.path.exists(path):
        return None
    return [path, "--smt2-model-format", "--bvconst-in-decimal"]


EXP_PRELUDE = (
    "(declare-fun p_x_uint256_aaaaaaa_00 () (_ BitVec 256))\n"
    "(declare-fun p_y_uint256_bbbbbbb_00 () (_ BitVec 256))\n"
    "(declare-fun f_evm_exp_256 ((_ BitVec 256) (_ BitVec 256)) (_ BitVec 256))\n"
)


def solve_exp_query(tmp_path, assertions: str, apps: ExpApps):
    command = yices_command()
    if command is None:
        pytest.skip("yices-smt2 not found")

    args = default_config().with_overrides(
        source=ConfigSource.command_line,
        solver_command=shlex.join(command),
        pretty_counterexamples=True,
    )
    ctx = PathContext(
        args=args,
        path_id=1,
        solving_ctx=SolvingContext(dump_dir=tmp_path),
        query=SMTQuery(EXP_PRELUDE + assertions, []),
        exp_apps=apps,
    )
    return solve_end_to_end(ctx)


X, Y = "p_x_uint256_aaaaaaa_00", "p_y_uint256_bbbbbbb_00"
BV3 = "(_ bv3 256)"


def test_exp_refinement_constant_exponent(tmp_path):
    # x ** 3 == 27: the abstraction allows any x, the real EXP only x == 3
    out = solve_exp_query(
        tmp_path,
        f"(assert (= (f_evm_exp_256 {X} {BV3}) (_ bv27 256)))\n",
        ExpApps((ExpApp(X, BV3, exponent_value=3),)),
    )
    assert out.result == sat
    assert out.model.is_valid
    assert out.model.model[X].value == 3


def test_exp_refinement_proves_absence(tmp_path):
    # 10 ** y == 5 has no solution, but the abstraction has one
    ten = "(_ bv10 256)"
    out = solve_exp_query(
        tmp_path,
        f"(assert (= (f_evm_exp_256 {ten} {Y}) (_ bv5 256)))\n",
        ExpApps((ExpApp(ten, Y, base_value=10),)),
    )
    assert str(out.result) == "unsat"


def test_exp_refinement_gives_up_with_a_reason(tmp_path):
    # x ** y == 3 with an even x has no solution, and infinitely many candidate points
    out = solve_exp_query(
        tmp_path,
        f"(assert (= (f_evm_exp_256 {X} {Y}) {BV3}))\n"
        f"(assert (= ((_ extract 0 0) {X}) #b0))\n"
        f"(assert (bvugt {Y} (_ bv0 256)))\n",
        ExpApps((ExpApp(X, Y),)),
    )
    assert out.result == sat
    assert not out.model.is_valid
    assert "symbolic base and exponent" in out.invalid_reason


def test_exp_arg_decls():
    decls = exp_arg_decls(ExpApps((ExpApp(X, BV3, exponent_value=3),)))
    assert f"(assert (= pcex_expb_0 {X}))" in decls
    assert "(assert (= pcex_expr_0 (f_evm_exp_256 pcex_expb_0 pcex_expe_0)))" in decls


#
# end to end, on tests/regression/test/PrettyCex.t.sol
#

ANSI_ESCAPE = __import__("re").compile(r"\x1b\[[0-9;]*m")


def run_pretty_cex_test(capsys, *args):
    from dolmos.__main__ import _main

    result = _main(["--root", "tests/regression", "--contract", "PrettyCexTest", *args])
    out = ANSI_ESCAPE.sub("", capsys.readouterr().out)
    return result.test_results["test/PrettyCex.t.sol:PrettyCexTest"], out


def test_pretty_counterexamples_end_to_end(capsys):
    # the state variables of the test (`token` below) are read through the solidity storage
    # layout: pin it, as the CI matrix also runs with --storage-layout generic
    results, out = run_pretty_cex_test(capsys, "-pcex", "--storage-layout", "solidity")

    # the verdicts and counts are the same as without the option
    assert {r.name: (r.exitcode, r.num_models) for r in results} == {
        "check_pcex_calldata(bytes)": (1, 1),
        "check_pcex_duplicates(uint256)": (1, 3),
        "check_pcex_exp(uint256)": (1, 1),
        "check_pcex_selector(bytes)": (1, 1),
        "invariant_pcex_balance()": (1, 1),
    }

    # halmos#398: duplicates are counted, not printed
    assert out.count("Counterexample: check_pcex_duplicates(uint256)\n    x = 0\n") == 1
    assert "2 duplicate counterexamples not shown" in out

    # halmos#280: the approximation of x ** 3 is refined, giving the real counterexample
    assert "Counterexample: check_pcex_exp(uint256)\n    x = 3\n" in out
    assert "potentially invalid" not in out

    # halmos#369: calldata decoded with the ABI of the target
    assert "    data = PcexToken.transfer(to: 0x" in out
    assert "trailing zero bytes\n" in out

    # halmos#419: the empty selector is explained
    assert "selector (bytes4) = 0x00000000 (no selector: empty calldata" in out
    assert 'this.check_pcex_selector("");' in out

    # invariant call sequence and its reproduction through the state variable of the test
    assert "        [1] PcexToken(token).transfer(to: 0x" in out
    assert "        token.transfer(0x" in out
    assert "        this.invariant_pcex_balance();" in out


def test_pretty_counterexamples_generic_storage_layout(capsys):
    # without the solidity storage layout, the state variable holding the target is unknown:
    # the call sequence falls back to the raw address, with a note in the reproduction
    results, out = run_pretty_cex_test(
        capsys,
        "-pcex",
        "--storage-layout",
        "generic",
        "--match-test",
        "^invariant_pcex_balance",
    )
    assert [(r.exitcode, r.num_models) for r in results] == [(1, 1)]
    assert "        [1] PcexToken@0x" in out
    assert "is the address of PcexToken in dolmos" in out


def test_early_exit_does_not_report_cancelled_queries(capsys, caplog):
    # halmos#398 requires --early-exit to work: the queries cancelled once a counterexample is
    # found are neither solver errors nor failed queries
    results, out = run_pretty_cex_test(
        capsys, "--match-test", "^check_pcex_duplicates", "--early-exit"
    )
    assert [(r.exitcode, r.num_models >= 1) for r in results] == [(1, True)]
    assert "executor has been shutdown" not in caplog.text
    assert "[ERROR]" not in out
    assert "Error queries saved" not in out
