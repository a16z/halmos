# SPDX-License-Identifier: AGPL-3.0

"""
vm.toString(...) cheatcodes (halmos#565), with foundry's formatting:

- address: EIP-55 checksummed hex, e.g. `0x7109709ECfa91a80626fF3989D68f67F5b1DD12D`
- bytes, bytes32: lowercase hex with a `0x` prefix
- bool: `true` or `false`
- uint256, int256: decimal, with a leading `-` for negative values

Concrete values are converted exactly. Symbolic values are supported too, since
forge-std calls vm.toString on values that are usually symbolic in dolmos tests
(e.g. `bound(int256, int256, int256)` logs its result with it):

- bytes, bytes32: exact, each hex digit is a symbolic character
- address: exact up to the case of the letters, which is left unconstrained instead
  of following the checksum (an over-approximation: every checksummed string is
  still a possible value)
- bool: exact, one path per feasible value, since the two strings differ in length
- uint256, int256: the length of the decimal string depends on the value, so it is
  approximated by a string of digits of the maximal length, with unconstrained
  digits, and a warning is printed
"""

from dataclasses import dataclass

from eth_hash.auto import keccak
from z3 import (
    UGE,
    ULE,
    And,
    BitVec,
    BitVecRef,
    BitVecVal,
    BoolRef,
    Concat,
    Extract,
    If,
    Or,
    is_bv,
    simplify,
    unsat,
)

from dolmos.bytevec import ByteVec
from dolmos.logs import warn
from dolmos.utils import extract_bytes_argument, is_bv_value, uid

# maximal number of decimal digits of an uint256 (2**256 - 1 has 78 digits)
MAX_UINT256_DIGITS = 78

# an int256 has at most 77 digits (2**255 has 77 digits), plus a sign
MAX_INT256_DIGITS = 77


@dataclass(frozen=True)
class ConditionalReturn:
    """
    Return data of a cheatcode that only holds under a condition.

    A cheatcode returning a list of ConditionalReturn creates one path per item,
    with the condition added to its path condition. Conditions must be feasible
    and mutually exclusive, and should cover every case.
    """

    cond: BoolRef
    data: ByteVec


def encode_string(data: bytes | BitVecRef) -> ByteVec:
    """ABI encoding of the return value `(string)`: offset, length, padded data"""
    length = data.size() // 8 if is_bv(data) else len(data)
    result = ByteVec((32).to_bytes(32, "big") + length.to_bytes(32, "big"))
    if length > 0:
        result.append(data)
        padding = (-length) % 32
        if padding:
            result.append(bytes(padding))
    return result


def checksum_address(value: int) -> str:
    """EIP-55 representation of an address"""
    hex_addr = f"{value:040x}"
    digest = keccak(hex_addr.encode()).hex()
    return "0x" + "".join(
        c.upper() if c.isalpha() and int(digest[i], 16) >= 8 else c
        for i, c in enumerate(hex_addr)
    )


def to_string_int(value: int, signed: bool) -> str:
    if signed and value >= 2**255:
        value -= 2**256
    return str(value)


def _concrete_word(word) -> int | None:
    word = simplify(word) if is_bv(word) else word
    if isinstance(word, int):
        return word
    if is_bv_value(word):
        return word.as_long()
    return None


def _hex_char(nibble: BitVecRef) -> BitVecRef:
    """ascii lowercase hex digit of a symbolic 4-bit value, as an 8-bit value"""
    byte = Concat(BitVecVal(0, 4), nibble)
    return If(
        ULE(byte, 9),
        byte + ord("0"),
        byte + (ord("a") - 10),
    )


def _symbolic_hex(data: BitVecRef) -> BitVecRef:
    """`0x` followed by the lowercase hex digits of a symbolic value"""
    nbits = data.size()
    chars = [BitVecVal(ord("0"), 8), BitVecVal(ord("x"), 8)]
    for hi in range(nbits - 1, 0, -4):
        chars.append(_hex_char(Extract(hi, hi - 3, data)))
    return simplify(Concat(*chars))


def _symbolic_address(value: BitVecRef, ex) -> BitVecRef:
    """
    `0x` followed by the hex digits of a symbolic address, each letter in either
    case: the checksum would need the keccak256 of the result, so the case of each
    letter is a fresh variable (constrained to the two valid characters).
    """
    case_bits = BitVec(f"tostring_address_case_{uid()}_{ex.new_symbol_id():>02}", 40)
    chars = [BitVecVal(ord("0"), 8), BitVecVal(ord("x"), 8)]
    for i in range(40):
        hi = 159 - 4 * i
        nibble = Extract(hi, hi - 3, value)
        lower = _hex_char(nibble)
        upper_bit = Extract(39 - i, 39 - i, case_bits)
        # 'a'..'f' minus 0x20 gives 'A'..'F'; digits keep their value
        is_letter = UGE(Concat(BitVecVal(0, 4), nibble), 10)
        chars.append(If(And(is_letter, upper_bit == 1), lower - 0x20, lower))
    return simplify(Concat(*chars))


def _symbolic_digits(ex, name: str, ndigits: int, signed: bool) -> BitVecRef:
    """
    A fresh string of `ndigits` decimal digits (and an optional leading `-` for
    signed values): the approximation of the decimal representation of a symbolic
    integer
    """
    nchars = ndigits + (1 if signed else 0)
    var = BitVec(f"tostring_{name}_{uid()}_{ex.new_symbol_id():>02}", 8 * nchars)
    for i in range(nchars):
        hi = 8 * nchars - 1 - 8 * i
        char = Extract(hi, hi - 7, var)
        is_digit = And(UGE(char, ord("0")), ULE(char, ord("9")))
        if signed and i == 0:
            ex.path.append(Or(is_digit, char == ord("-")))
        else:
            ex.path.append(is_digit)
    return var


def to_string_cheatcode(funsig: int, arg: ByteVec, ex) -> ByteVec | list:
    """
    Handle the vm.toString(...) overloads, given the function selector and the
    calldata of the call.
    """
    if funsig == TO_STRING_BYTES:
        data = extract_bytes_argument(arg, 0)
        if is_bv(data):
            data = simplify(data)
            if is_bv_value(data):
                nbytes = data.size() // 8
                data = data.as_long().to_bytes(nbytes, "big")
        if isinstance(data, bytes | bytearray):
            return encode_string(("0x" + bytes(data).hex()).encode())
        return encode_string(_symbolic_hex(data))

    word = arg.get_word(4)
    value = _concrete_word(word)

    if funsig == TO_STRING_BYTES32:
        if value is not None:
            return encode_string(f"0x{value:064x}".encode())
        return encode_string(_symbolic_hex(word))

    if funsig == TO_STRING_ADDRESS:
        if value is not None:
            return encode_string(checksum_address(value % 2**160).encode())
        return encode_string(_symbolic_address(Extract(159, 0, word), ex))

    if funsig == TO_STRING_BOOL:
        if value is not None:
            return encode_string(b"true" if value != 0 else b"false")
        is_true = simplify(word != 0)
        results = []
        for cond, text in ((is_true, b"true"), (simplify(word == 0), b"false")):
            if ex.check(cond) != unsat:
                results.append(ConditionalReturn(cond, encode_string(text)))
        return results

    if funsig in (TO_STRING_UINT256, TO_STRING_INT256):
        signed = funsig == TO_STRING_INT256
        if value is not None:
            return encode_string(to_string_int(value, signed).encode())
        type_name = "int256" if signed else "uint256"
        warn(
            f"vm.toString({type_name}) of a symbolic value is approximated by a "
            "string of unconstrained digits of the maximal length",
            allow_duplicate=False,
        )
        ndigits = MAX_INT256_DIGITS if signed else MAX_UINT256_DIGITS
        return encode_string(_symbolic_digits(ex, type_name, ndigits, signed))

    raise ValueError(f"not a vm.toString selector: 0x{funsig:08x}")


# bytes4(keccak256("toString(address)")), etc.
TO_STRING_ADDRESS = 0x56CA623E
TO_STRING_BYTES = 0x71AAD10D
TO_STRING_BYTES32 = 0xB11A19E8
TO_STRING_BOOL = 0x71DCE7DA
TO_STRING_UINT256 = 0x6900A3AE
TO_STRING_INT256 = 0xA322C40E

TO_STRING_SIGNATURES = frozenset(
    {
        TO_STRING_ADDRESS,
        TO_STRING_BYTES,
        TO_STRING_BYTES32,
        TO_STRING_BOOL,
        TO_STRING_UINT256,
        TO_STRING_INT256,
    }
)
