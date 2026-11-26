from z3 import BitVec, Extract

from dolmos.pcex import (
    AddressLabel,
    RenderContext,
    Segment,
    address_hints,
    collect_labels,
    resolve_labels,
)
from dolmos.solve import ModelVariable, PotentialModel


def var(name: str, value: int, size: int = 160) -> ModelVariable:
    parts = name.split("_")
    return ModelVariable(
        full_name=name,
        variable_name=parts[1],
        solidity_type=parts[2],
        smt_type=f"BitVec {size}",
        size_bits=size,
        value=value,
    )


class FakeEx:
    def __init__(self, labels):
        self.labels = labels


def test_collect_and_resolve_labels():
    bob = BitVec("dolmos_bob_address_abc1234_01", 160)
    word = BitVec("p_x_uint256_def5678_00", 256)
    ex = FakeEx(
        [
            (BitVec("unused", 160) * 3, "dropped: not made of symbols"),
            (bob, "bob"),
            (Extract(159, 0, word), "x"),
        ]
    )
    labels = collect_labels(ex)
    assert [label.label for label in labels] == ["bob", "x"]

    model = {
        "dolmos_bob_address_abc1234_01": var("dolmos_bob_address_abc1234_01", 0xB0B),
        "p_x_uint256_def5678_00": var("p_x_uint256_def5678_00", 2**200 + 0xCAFE, 256),
    }
    assert resolve_labels(labels, model) == {0xB0B: "bob", 0xCAFE: "x"}


def test_latest_label_wins():
    labels = (
        AddressLabel(segments=(Segment(const=0xA, size=160),), label="first"),
        AddressLabel(segments=(Segment(const=0xA, size=160),), label="second"),
    )
    assert resolve_labels(labels, {}) == {0xA: "second"}


def test_address_hints_combine_labels_and_contracts():
    labels = (AddressLabel(segments=(Segment(const=0xC, size=160),), label="vault"),)
    hints = address_hints({0xC: "Vault", 0xD: "Token"}, labels, {})
    assert hints == {0xC: "vault, Vault", 0xD: "Token"}


def test_render_context_uses_labels():
    labels = (
        AddressLabel(
            segments=(Segment(symbol="dolmos_bob_address_abc1234_01", size=160),),
            label="bob",
        ),
    )
    ctx = RenderContext(addr_names={0xB0B: "Wallet"}, labels=labels)
    model = {
        "dolmos_bob_address_abc1234_01": var("dolmos_bob_address_abc1234_01", 0xB0B)
    }
    assert ctx.address_hint(0xB0B) == "Wallet"
    assert ctx.with_model(model).address_hint(0xB0B) == "bob, Wallet"


def test_potential_model_render_annotates_addresses():
    model = PotentialModel(
        model={
            "p_user_address_1234567_00": var("p_user_address_1234567_00", 0xA11CE),
            # same value, but not an address: not annotated
            "p_n_uint256_1234567_01": var("p_n_uint256_1234567_01", 0xA11CE, 256),
        },
        is_valid=True,
    )
    rendered = model.render({0xA11CE: "alice"})
    assert "p_user_address_1234567_00 = 0xa11ce (alice)" in rendered
    assert "p_n_uint256_1234567_01 = 0xa11ce\n" in rendered + "\n"
    # without hints, the rendering is unchanged
    assert str(model) == model.render(None)
    assert "(alice)" not in str(model)
