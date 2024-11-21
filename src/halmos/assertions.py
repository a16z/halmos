# SPDX-License-Identifier: AGPL-3.0

import re
from dataclasses import dataclass

from z3 import (
    UGE,
    UGT,
    ULE,
    ULT,
    BitVecRef,
    BoolVal,
    is_bv,
)

from .exceptions import HalmosException
from .utils import (
    bytes_to_bv_value,
    extract_bytes,
    extract_bytes32_array_argument,
    extract_bytes_argument,
    extract_string_argument,
    test,
    uint256,
)


@dataclass(frozen=True)
class VmAssertion:
    """
    Forge Standard Assertions
    """

    cond: BitVecRef
    msg: str | None


def is_empty_bytes(x) -> bool:
    return isinstance(x, bytes) and not x


def mk_cond(bop, v1, v2):
    # handle empty arguments
    if is_empty_bytes(v1) and is_empty_bytes(v2):
        if bop == "Eq":
            return BoolVal(True)
        elif bop == "NotEq":
            return BoolVal(False)
        else:
            raise ValueError(f"mk_cond: invalid arguments: {v1} {bop} {v2}")

    elif is_empty_bytes(v1) or is_empty_bytes(v2):
        if bop == "Eq":
            return BoolVal(False)
        elif bop == "NotEq":
            return BoolVal(True)
        else:
            raise ValueError(f"mk_cond: invalid arguments: {v1} {bop} {v2}")

    # now both arguments are non-empty

    v1 = bytes_to_bv_value(v1) if isinstance(v1, bytes) else v1
    v2 = bytes_to_bv_value(v2) if isinstance(v2, bytes) else v2

    if not is_bv(v1):
        raise ValueError(f"mk_cond: not bv: {v1}")
    if not is_bv(v2):
        raise ValueError(f"mk_cond: not bv: {v2}")

    # for Eq and NotEq, the bitsize can be arbitrary, e.g., arrays

    if v1.size() != v2.size():
        if bop == "Eq":
            return BoolVal(False)
        elif bop == "NotEq":
            return BoolVal(True)
        else:
            raise ValueError(f"mk_cond: incompatible size: {v1} {bop} {v2}")

    if bop == "Eq":
        return v1 == v2
    elif bop == "NotEq":
        return v1 != v2

    # for comparison operators, the bitsize must be 256-bit

    if v1.size() != 256 or v2.size() != 256:
        raise ValueError(f"mk_cond: incompatible size: {v1} {bop} {v2}")

    if bop == "ULt":
        return ULT(v1, v2)
    elif bop == "UGt":
        return UGT(v1, v2)
    elif bop == "ULe":
        return ULE(v1, v2)
    elif bop == "UGe":
        return UGE(v1, v2)
    elif bop == "SLt":
        return v1 < v2
    elif bop == "SGt":
        return v1 > v2
    elif bop == "SLe":
        return v1 <= v2
    elif bop == "SGe":
        return v1 >= v2
    else:
        raise ValueError(f"mk_cond: unknown bop: {bop}")


def vm_assert_binary(bop: str, typ: str, log: bool = False):
    arr = typ.endswith("[]")
    typ = typ.replace("[]", "")

    is_bytes = typ in ["bytes", "string"]

    if not arr:
        # bool, uint256, int256, address, bytes32
        if not is_bytes:

            def _f(arg):
                v1 = extract_bytes(arg, 4, 32)
                v2 = extract_bytes(arg, 36, 32)
                cond = mk_cond(bop, v1, v2)
                msg = extract_string_argument(arg, 2) if log else None
                return VmAssertion(cond, msg)

            return _f

        # bytes, string
        else:

            def _f(arg):
                v1 = extract_bytes_argument(arg, 0)
                v2 = extract_bytes_argument(arg, 1)
                cond = mk_cond(bop, v1, v2)
                msg = extract_string_argument(arg, 2) if log else None
                return VmAssertion(cond, msg)

            return _f

    else:
        # bool[], uint256[], int256[], address[], bytes32[]
        if not is_bytes:

            def _f(arg):
                v1 = extract_bytes32_array_argument(arg, 0)
                v2 = extract_bytes32_array_argument(arg, 1)
                cond = mk_cond(bop, v1, v2)
                msg = extract_string_argument(arg, 2) if log else None
                return VmAssertion(cond, msg)

            return _f

        # bytes[], string[]
        else:

            def _f(arg):
                # TODO: implement extract_bytes_array
                raise NotImplementedError(f"assert {bop} {typ}[]")

            return _f


def vm_assert_unary(expected: bool, log: bool = False):
    def _f(arg):
        actual = uint256(arg.get_word(4))
        cond = test(actual, expected)
        msg = extract_string_argument(arg, 1) if log else None
        return VmAssertion(cond, msg)

    return _f


def mk_assert_handler(signature):
    # pattern: assert<operator>(<params>)
    match = re.search(r"assert([^(]+)\(([^)]+)\)", signature)
    if match:
        operator = match.group(1)
        params = match.group(2).split(",")
    else:
        raise HalmosException(f"not supported signatures: {signature}")

    # operator type:
    # - binary: compare two arguments
    # - unary: check given condition
    is_binary = operator not in ["True", "False"]

    # whether it includes log message or not
    has_log = len(params) > (2 if is_binary else 1)

    if is_binary:
        typ = params[0]  # params[0] == params[1]
        if operator in ["Eq", "NotEq"]:
            bop = operator
        else:
            # for comparison operators, we need to identify whether they are unsigned or signed
            sign = "U" if typ == "uint256" else "S"
            bop = sign + operator
        return vm_assert_binary(bop, typ, has_log)
    else:
        return vm_assert_unary(operator == "True", has_log)


assert_cheatcode_handler = {
    # assertTrue/False
    0x0C9FD581: mk_assert_handler("assertTrue(bool)"),
    0xA34EDC03: mk_assert_handler("assertTrue(bool,string)"),
    0xA5982885: mk_assert_handler("assertFalse(bool)"),
    0x7BA04809: mk_assert_handler("assertFalse(bool,string)"),
    # assertEq(T, T)
    0xF7FE3477: mk_assert_handler("assertEq(bool,bool)"),
    0x4DB19E7E: mk_assert_handler("assertEq(bool,bool,string)"),
    0x98296C54: mk_assert_handler("assertEq(uint256,uint256)"),
    0x88B44C85: mk_assert_handler("assertEq(uint256,uint256,string)"),
    0xFE74F05B: mk_assert_handler("assertEq(int256,int256)"),
    0x714A2F13: mk_assert_handler("assertEq(int256,int256,string)"),
    0x515361F6: mk_assert_handler("assertEq(address,address)"),
    0x2F2769D1: mk_assert_handler("assertEq(address,address,string)"),
    0x7C84C69B: mk_assert_handler("assertEq(bytes32,bytes32)"),
    0xC1FA1ED0: mk_assert_handler("assertEq(bytes32,bytes32,string)"),
    0xF320D963: mk_assert_handler("assertEq(string,string)"),
    0x36F656D8: mk_assert_handler("assertEq(string,string,string)"),
    0x97624631: mk_assert_handler("assertEq(bytes,bytes)"),
    0xE24FED00: mk_assert_handler("assertEq(bytes,bytes,string)"),
    # assertEq(T[], T[])
    0x707DF785: mk_assert_handler("assertEq(bool[],bool[])"),
    0xE48A8F8D: mk_assert_handler("assertEq(bool[],bool[],string)"),
    0x975D5A12: mk_assert_handler("assertEq(uint256[],uint256[])"),
    0x5D18C73A: mk_assert_handler("assertEq(uint256[],uint256[],string)"),
    0x711043AC: mk_assert_handler("assertEq(int256[],int256[])"),
    0x191F1B30: mk_assert_handler("assertEq(int256[],int256[],string)"),
    0x3868AC34: mk_assert_handler("assertEq(address[],address[])"),
    0x3E9173C5: mk_assert_handler("assertEq(address[],address[],string)"),
    0x0CC9EE84: mk_assert_handler("assertEq(bytes32[],bytes32[])"),
    0xE03E9177: mk_assert_handler("assertEq(bytes32[],bytes32[],string)"),
    0xCF1C049C: mk_assert_handler("assertEq(string[],string[])"),
    0xEFF6B27D: mk_assert_handler("assertEq(string[],string[],string)"),
    0xE5FB9B4A: mk_assert_handler("assertEq(bytes[],bytes[])"),
    0xF413F0B6: mk_assert_handler("assertEq(bytes[],bytes[],string)"),
    # assertNotEq(T, T)
    0x236E4D66: mk_assert_handler("assertNotEq(bool,bool)"),
    0x1091A261: mk_assert_handler("assertNotEq(bool,bool,string)"),
    0xB7909320: mk_assert_handler("assertNotEq(uint256,uint256)"),
    0x98F9BDBD: mk_assert_handler("assertNotEq(uint256,uint256,string)"),
    0xF4C004E3: mk_assert_handler("assertNotEq(int256,int256)"),
    0x4724C5B9: mk_assert_handler("assertNotEq(int256,int256,string)"),
    0xB12E1694: mk_assert_handler("assertNotEq(address,address)"),
    0x8775A591: mk_assert_handler("assertNotEq(address,address,string)"),
    0x898E83FC: mk_assert_handler("assertNotEq(bytes32,bytes32)"),
    0xB2332F51: mk_assert_handler("assertNotEq(bytes32,bytes32,string)"),
    0x6A8237B3: mk_assert_handler("assertNotEq(string,string)"),
    0x78BDCEA7: mk_assert_handler("assertNotEq(string,string,string)"),
    0x3CF78E28: mk_assert_handler("assertNotEq(bytes,bytes)"),
    0x9507540E: mk_assert_handler("assertNotEq(bytes,bytes,string)"),
    # assertNotEq(T[], T[])
    0x286FAFEA: mk_assert_handler("assertNotEq(bool[],bool[])"),
    0x62C6F9FB: mk_assert_handler("assertNotEq(bool[],bool[],string)"),
    0x56F29CBA: mk_assert_handler("assertNotEq(uint256[],uint256[])"),
    0x9A7FBD8F: mk_assert_handler("assertNotEq(uint256[],uint256[],string)"),
    0x0B72F4EF: mk_assert_handler("assertNotEq(int256[],int256[])"),
    0xD3977322: mk_assert_handler("assertNotEq(int256[],int256[],string)"),
    0x46D0B252: mk_assert_handler("assertNotEq(address[],address[])"),
    0x72C7E0B5: mk_assert_handler("assertNotEq(address[],address[],string)"),
    0x0603EA68: mk_assert_handler("assertNotEq(bytes32[],bytes32[])"),
    0xB873634C: mk_assert_handler("assertNotEq(bytes32[],bytes32[],string)"),
    0xBDFACBE8: mk_assert_handler("assertNotEq(string[],string[])"),
    0xB67187F3: mk_assert_handler("assertNotEq(string[],string[],string)"),
    0xEDECD035: mk_assert_handler("assertNotEq(bytes[],bytes[])"),
    0x1DCD1F68: mk_assert_handler("assertNotEq(bytes[],bytes[],string)"),
    # assertLt/Gt/Le/Ge
    0xB12FC005: mk_assert_handler("assertLt(uint256,uint256)"),
    0x65D5C135: mk_assert_handler("assertLt(uint256,uint256,string)"),
    0x3E914080: mk_assert_handler("assertLt(int256,int256)"),
    0x9FF531E3: mk_assert_handler("assertLt(int256,int256,string)"),
    0xDB07FCD2: mk_assert_handler("assertGt(uint256,uint256)"),
    0xD9A3C4D2: mk_assert_handler("assertGt(uint256,uint256,string)"),
    0x5A362D45: mk_assert_handler("assertGt(int256,int256)"),
    0xF8D33B9B: mk_assert_handler("assertGt(int256,int256,string)"),
    0x8466F415: mk_assert_handler("assertLe(uint256,uint256)"),
    0xD17D4B0D: mk_assert_handler("assertLe(uint256,uint256,string)"),
    0x95FD154E: mk_assert_handler("assertLe(int256,int256)"),
    0x4DFE692C: mk_assert_handler("assertLe(int256,int256,string)"),
    0xA8D4D1D9: mk_assert_handler("assertGe(uint256,uint256)"),
    0xE25242C0: mk_assert_handler("assertGe(uint256,uint256,string)"),
    0x0A30B771: mk_assert_handler("assertGe(int256,int256)"),
    0xA84328DD: mk_assert_handler("assertGe(int256,int256,string)"),
}
