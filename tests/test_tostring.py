import pytest
from z3 import BitVec, BitVecVal, Solver, sat, simplify, substitute

from dolmos.bytevec import ByteVec
from dolmos.tostring import (
    TO_STRING_ADDRESS,
    TO_STRING_BOOL,
    TO_STRING_BYTES,
    TO_STRING_BYTES32,
    TO_STRING_INT256,
    TO_STRING_UINT256,
    ConditionalReturn,
    checksum_address,
    to_string_cheatcode,
)


class FakePath:
    def __init__(self):
        self.conds = []

    def append(self, cond, branching=False):
        self.conds.append(cond)


class FakeEx:
    """the parts of Exec used by vm.toString"""

    def __init__(self):
        self.path = FakePath()
        self._id = 0

    def new_symbol_id(self):
        self._id += 1
        return self._id

    def check(self, cond):
        s = Solver()
        s.add(*self.path.conds, cond)
        return s.check()


def word(x: int) -> bytes:
    return x.to_bytes(32, "big")


def decode(ret: ByteVec, subst=()) -> str:
    """decode an abi-encoded string, after substituting symbolic values"""
    data = ret.unwrap()
    if not isinstance(data, bytes | bytearray):
        data = simplify(substitute(data, *subst))
        data = data.as_long().to_bytes(len(ret), "big")
    length = int.from_bytes(data[32:64], "big")
    assert len(data) % 32 == 0
    return data[64 : 64 + length].decode()


def call(sig: int, payload, ex=None) -> ByteVec | list:
    return to_string_cheatcode(sig, ByteVec(sig.to_bytes(4, "big") + payload), ex)


def test_checksum_address():
    # test vectors of EIP-55
    for addr in [
        "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed",
        "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359",
        "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB",
        "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb",
    ]:
        assert checksum_address(int(addr, 16)) == addr


@pytest.mark.parametrize(
    "sig, payload, expected",
    [
        (TO_STRING_ADDRESS, word(0), "0x" + "0" * 40),
        (TO_STRING_BYTES32, word(0xABC), "0x" + "0" * 61 + "abc"),
        (TO_STRING_BOOL, word(1), "true"),
        (TO_STRING_BOOL, word(0), "false"),
        (TO_STRING_UINT256, word(0), "0"),
        (TO_STRING_UINT256, word(2**256 - 1), str(2**256 - 1)),
        (TO_STRING_INT256, word(2**256 - 42), "-42"),
        (TO_STRING_INT256, word(2**255), str(-(2**255))),
        (TO_STRING_INT256, word(2**255 - 1), str(2**255 - 1)),
        (
            TO_STRING_BYTES,
            word(32) + word(3) + bytes.fromhex("00ff10") + bytes(29),
            "0x00ff10",
        ),
        (TO_STRING_BYTES, word(32) + word(0), "0x"),
    ],
)
def test_to_string_concrete(sig, payload, expected):
    assert decode(call(sig, payload)) == expected


def test_to_string_bytes32_symbolic():
    x = BitVec("x", 256)
    arg = ByteVec(TO_STRING_BYTES32.to_bytes(4, "big"))
    arg.append(x)
    ret = to_string_cheatcode(TO_STRING_BYTES32, arg, FakeEx())
    value = 0x0123456789ABCDEF << 192
    assert decode(ret, [(x, BitVecVal(value, 256))]) == f"0x{value:064x}"


def test_to_string_bytes_symbolic():
    x = BitVec("x", 32)
    arg = ByteVec(TO_STRING_BYTES.to_bytes(4, "big") + word(32) + word(4))
    arg.append(x)
    arg.append(bytes(28))
    ret = to_string_cheatcode(TO_STRING_BYTES, arg, FakeEx())
    assert decode(ret, [(x, BitVecVal(0xDEADBEEF, 32))]) == "0xdeadbeef"


def test_to_string_address_symbolic():
    a = BitVec("a", 160)
    arg = ByteVec(TO_STRING_ADDRESS.to_bytes(4, "big") + bytes(12))
    arg.append(a)
    ex = FakeEx()
    ret = to_string_cheatcode(TO_STRING_ADDRESS, arg, ex)

    value = 0x5AAEB6053F3E94C9B9A09F33669435E7EF1BEAED
    data = ret.unwrap()
    # the checksummed string is a possible value, and so is the lowercase one
    for text in [checksum_address(value), f"0x{value:040x}"]:
        s = Solver()
        s.add(a == value)
        s.add(data == BitVecVal(int.from_bytes(encode(text), "big"), data.size()))
        assert s.check() == sat
    # but the digits are exact
    s = Solver()
    s.add(a == value)
    wrong = "0x" + "6" + f"{value:040x}"[1:]
    s.add(data == BitVecVal(int.from_bytes(encode(wrong), "big"), data.size()))
    assert s.check() != sat


def encode(text: str) -> bytes:
    data = text.encode()
    return word(32) + word(len(data)) + data + bytes(-len(data) % 32)


def test_to_string_bool_symbolic():
    b = BitVec("b", 256)
    arg = ByteVec(TO_STRING_BOOL.to_bytes(4, "big"))
    arg.append(b)
    results = to_string_cheatcode(TO_STRING_BOOL, arg, FakeEx())
    assert len(results) == 2
    assert all(isinstance(r, ConditionalReturn) for r in results)
    assert {decode(r.data) for r in results} == {"true", "false"}

    # a path where b is known to be true has a single result
    ex = FakeEx()
    ex.path.append(b == 1)
    results = to_string_cheatcode(TO_STRING_BOOL, arg, ex)
    assert [decode(r.data) for r in results] == ["true"]


@pytest.mark.parametrize(
    "sig, nchars", [(TO_STRING_UINT256, 78), (TO_STRING_INT256, 78)]
)
def test_to_string_int_symbolic_is_approximated(sig, nchars):
    x = BitVec("x", 256)
    arg = ByteVec(sig.to_bytes(4, "big"))
    arg.append(x)
    ex = FakeEx()
    ret = to_string_cheatcode(sig, arg, ex)
    assert len(ret) == 64 + 96  # 78 chars, padded to 96 bytes
    # every character is a digit (or a sign, for the first one of an int)
    s = Solver()
    s.add(*ex.path.conds)
    assert s.check() == sat
    assert int.from_bytes(bytes(ret[32:64].unwrap()), "big") == nchars
