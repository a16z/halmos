import pytest
from eth_hash.auto import keccak
from z3 import is_false, is_true, simplify

from halmos.assertions import assert_cheatcode_handler
from halmos.bytevec import ByteVec

UINT_MAX = 2**256 - 1
INT_MAX = 2**255 - 1
INT_MIN = -(2**255)


def selector(signature: str) -> int:
    return int.from_bytes(keccak(signature.encode())[:4], "big")


def calldata(signature: str, *words: int, msg: str | None = None) -> ByteVec:
    """abi-encodes static words, then an optional string, after the selector"""
    head = b"".join((w % 2**256).to_bytes(32, "big") for w in words)
    tail = b""
    if msg is not None:
        head += (32 * (len(words) + 1)).to_bytes(32, "big")
        data = msg.encode()
        tail = len(data).to_bytes(32, "big") + data.ljust(
            -(-len(data) // 32) * 32, b"\0"
        )
    return ByteVec(selector(signature).to_bytes(4, "big") + head + tail)


def holds(signature: str, *words: int, msg: str | None = None) -> bool:
    cond = simplify(
        assert_cheatcode_handler[selector(signature)](
            calldata(signature, *words, msg=msg)
        ).cond
    )
    assert is_true(cond) or is_false(cond), cond
    return is_true(cond)


APPROX_EQ_ABS = [
    "assertApproxEqAbs(uint256,uint256,uint256)",
    "assertApproxEqAbs(uint256,uint256,uint256,string)",
    "assertApproxEqAbs(int256,int256,uint256)",
    "assertApproxEqAbs(int256,int256,uint256,string)",
    "assertApproxEqAbsDecimal(uint256,uint256,uint256,uint256)",
    "assertApproxEqAbsDecimal(uint256,uint256,uint256,uint256,string)",
    "assertApproxEqAbsDecimal(int256,int256,uint256,uint256)",
    "assertApproxEqAbsDecimal(int256,int256,uint256,uint256,string)",
]


@pytest.mark.parametrize("signature", APPROX_EQ_ABS)
def test_approx_eq_abs_is_supported(signature):
    assert selector(signature) in assert_cheatcode_handler


# (left, right, maxDelta, holds): the boundary cases, where |left - right| == maxDelta
UINT_CASES = [
    (5, 3, 2, True),
    (5, 3, 1, False),
    (3, 5, 2, True),
    (3, 5, 1, False),
    (7, 7, 0, True),
    (0, UINT_MAX, UINT_MAX, True),
    (0, UINT_MAX, UINT_MAX - 1, False),
]

INT_CASES = [
    (-1, 1, 2, True),
    (-1, 1, 1, False),
    (-5, -3, 2, True),
    (-5, -3, 1, False),
    (INT_MIN, INT_MIN, 0, True),
    (INT_MIN, -1, 2**255 - 1, True),
    (INT_MIN, -1, 2**255 - 2, False),
    (0, INT_MIN, 2**255, True),
    (0, INT_MIN, 2**255 - 1, False),
    (INT_MAX, INT_MIN, UINT_MAX, True),
    (INT_MAX, INT_MIN, UINT_MAX - 1, False),
    (INT_MIN, INT_MAX, UINT_MAX, True),
    (INT_MIN, INT_MAX, UINT_MAX - 1, False),
]


@pytest.mark.parametrize("left, right, max_delta, expected", UINT_CASES)
def test_approx_eq_abs_uint(left, right, max_delta, expected):
    assert (
        holds("assertApproxEqAbs(uint256,uint256,uint256)", left, right, max_delta)
        == expected
    )
    assert (
        holds(
            "assertApproxEqAbs(uint256,uint256,uint256,string)",
            left,
            right,
            max_delta,
            msg="m",
        )
        == expected
    )
    # decimals only change how forge prints the values
    for decimals in [0, 18]:
        sig = "assertApproxEqAbsDecimal(uint256,uint256,uint256,uint256)"
        assert holds(sig, left, right, max_delta, decimals) == expected


@pytest.mark.parametrize("left, right, max_delta, expected", INT_CASES)
def test_approx_eq_abs_int(left, right, max_delta, expected):
    assert (
        holds("assertApproxEqAbs(int256,int256,uint256)", left, right, max_delta)
        == expected
    )
    assert (
        holds(
            "assertApproxEqAbs(int256,int256,uint256,string)",
            left,
            right,
            max_delta,
            msg="m",
        )
        == expected
    )
    for decimals in [0, 18]:
        sig = "assertApproxEqAbsDecimal(int256,int256,uint256,uint256)"
        assert holds(sig, left, right, max_delta, decimals) == expected


@pytest.mark.parametrize(
    "signature, words",
    [
        ("assertApproxEqAbs(uint256,uint256,uint256,string)", (1, 2, 3)),
        ("assertApproxEqAbs(int256,int256,uint256,string)", (-1, 2, 3)),
        (
            "assertApproxEqAbsDecimal(uint256,uint256,uint256,uint256,string)",
            (1, 2, 3, 18),
        ),
        (
            "assertApproxEqAbsDecimal(int256,int256,uint256,uint256,string)",
            (-1, 2, 3, 18),
        ),
    ],
)
def test_approx_eq_abs_message(signature, words):
    handler = assert_cheatcode_handler[selector(signature)]
    assert (
        handler(calldata(signature, *words, msg="too far apart")).msg == "too far apart"
    )


def test_approx_eq_abs_no_message():
    signature = "assertApproxEqAbsDecimal(uint256,uint256,uint256,uint256)"
    handler = assert_cheatcode_handler[selector(signature)]
    assert handler(calldata(signature, 1, 2, 3, 18)).msg is None
