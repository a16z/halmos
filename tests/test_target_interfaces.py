from dolmos.__main__ import abi_decode_FuzzInterface_array
from dolmos.bytevec import ByteVec


def w(x: int) -> bytes:
    return x.to_bytes(32, "big")


def enc_string(s: str) -> bytes:
    data = s.encode()
    return w(len(data)) + data + bytes(-len(data) % 32)


def enc_string_array(names: list[str]) -> bytes:
    heads, tails = [], b""
    for name in names:
        heads.append(w(32 * len(names) + len(tails)))
        tails += enc_string(name)
    return w(len(names)) + b"".join(heads) + tails


def enc_interfaces(items: list[tuple[int, list[str]]]) -> bytes:
    """abi.encode(FuzzInterface[]) where FuzzInterface is (address, string[])"""
    heads, tails = [], b""
    for addr, names in items:
        heads.append(w(32 * len(items) + len(tails)))
        tails += w(addr) + w(64) + enc_string_array(names)
    return w(32) + w(len(items)) + b"".join(heads) + tails


def test_decode_fuzz_interfaces():
    data = enc_interfaces(
        [(0xCCCC0001, ["ProxyVault"]), (0xAA, ["src/A.sol:A", "IB"]), (0xBB, [])]
    )
    decoded = [
        (addr.as_long(), names)
        for addr, names in abi_decode_FuzzInterface_array(ByteVec(data))
    ]
    assert decoded == [
        (0xCCCC0001, ["ProxyVault"]),
        (0xAA, ["src/A.sol:A", "IB"]),
        (0xBB, []),
    ]
