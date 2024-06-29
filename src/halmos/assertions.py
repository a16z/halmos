# SPDX-License-Identifier: AGPL-3.0

from dataclasses import dataclass
from z3 import *

from .utils import *


@dataclass(frozen=True)
class VmAssertion:
    """
    Forge Standard Assertions
    """

    cond: BitVecRef
    msg: Optional


def mk_cond(bop, v1, v2):
    v1 = bytes_to_bv_value(v1) if isinstance(v1, bytes) else v1
    v2 = bytes_to_bv_value(v2) if isinstance(v2, bytes) else v2

    if not is_bv(v1):
        raise ValueError(f"mk_cond: not bv: {v1}")
    if not is_bv(v2):
        raise ValueError(f"mk_cond: not bv: {v2}")

    if v1.size() != v2.size():
        if bop == "eq":
            return BoolVal(False)
        elif bop == "neq":
            return BoolVal(True)
        else:
            raise ValueError(f"mk_cond: incompatible size: {v1} {bop} {v2}")

    if bop == "eq":
        return v1 == v2
    elif bop == "neq":
        return v1 != v2
    else:
        if v1.size() != 256 or v2.size() != 256:
            raise ValueError(f"mk_cond: incompatible size: {v1} {bop} {v2}")
        elif bop == "ult":
            return ULT(v1, v2)
        elif bop == "ugt":
            return UGT(v1, v2)
        elif bop == "ule":
            return ULE(v1, v2)
        elif bop == "uge":
            return UGE(v1, v2)
        elif bop == "slt":
            return v1 < v2
        elif bop == "sgt":
            return v1 > v2
        elif bop == "sle":
            return v1 <= v2
        elif bop == "sge":
            return v1 >= v2
        else:
            raise ValueError(f"mk_cond: unknown bop: {bop}")


def vm_assert(bop: str, typ: str, log: bool = False):
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


def vm_assert0(expected: bool, log: bool = False):
    def _f(arg):
        actual = uint256(arg.get_word(4))
        cond = test(actual, expected)
        msg = extract_string_argument(arg, 1) if log else None
        return VmAssertion(cond, msg)

    return _f


assert_cheatcode_handler = {
    # assertTrue/False
    0x0C9FD581: vm_assert0(True),
    0xA34EDC03: vm_assert0(True, log=True),
    0xA5982885: vm_assert0(False),
    0x7BA04809: vm_assert0(False, log=True),
    # assertEq(T, T)
    0xF7FE3477: vm_assert("eq", "bool"),
    0x4DB19E7E: vm_assert("eq", "bool", log=True),
    0x98296C54: vm_assert("eq", "uint256"),
    0x88B44C85: vm_assert("eq", "uint256", log=True),
    0xFE74F05B: vm_assert("eq", "int256"),
    0x714A2F13: vm_assert("eq", "int256", log=True),
    0x515361F6: vm_assert("eq", "address"),
    0x2F2769D1: vm_assert("eq", "address", log=True),
    0x7C84C69B: vm_assert("eq", "bytes32"),
    0xC1FA1ED0: vm_assert("eq", "bytes32", log=True),
    0xF320D963: vm_assert("eq", "string"),
    0x36F656D8: vm_assert("eq", "string", log=True),
    0x97624631: vm_assert("eq", "bytes"),
    0xE24FED00: vm_assert("eq", "bytes", log=True),
    # assertEq(T[], T[])
    0x707DF785: vm_assert("eq", "bool[]"),
    0xE48A8F8D: vm_assert("eq", "bool[]", log=True),
    0x975D5A12: vm_assert("eq", "uint256[]"),
    0x5D18C73A: vm_assert("eq", "uint256[]", log=True),
    0x711043AC: vm_assert("eq", "int256[]"),
    0x191F1B30: vm_assert("eq", "int256[]", log=True),
    0x3868AC34: vm_assert("eq", "address[]"),
    0x3E9173C5: vm_assert("eq", "address[]", log=True),
    0x0CC9EE84: vm_assert("eq", "bytes32[]"),
    0xE03E9177: vm_assert("eq", "bytes32[]", log=True),
    0xCF1C049C: vm_assert("eq", "string[]"),
    0xEFF6B27D: vm_assert("eq", "string[]", log=True),
    0xE5FB9B4A: vm_assert("eq", "bytes[]"),
    0xF413F0B6: vm_assert("eq", "bytes[]", log=True),
    # assertNotEq(T, T)
    0x236E4D66: vm_assert("neq", "bool"),
    0x1091A261: vm_assert("neq", "bool", log=True),
    0xB7909320: vm_assert("neq", "uint256"),
    0x98F9BDBD: vm_assert("neq", "uint256", log=True),
    0xF4C004E3: vm_assert("neq", "int256"),
    0x4724C5B9: vm_assert("neq", "int256", log=True),
    0xB12E1694: vm_assert("neq", "address"),
    0x8775A591: vm_assert("neq", "address", log=True),
    0x898E83FC: vm_assert("neq", "bytes32"),
    0xB2332F51: vm_assert("neq", "bytes32", log=True),
    0x6A8237B3: vm_assert("neq", "string"),
    0x78BDCEA7: vm_assert("neq", "string", log=True),
    0x9507540E: vm_assert("neq", "bytes"),
    0x3CF78E28: vm_assert("neq", "bytes", log=True),
    # assertNotEq(T[], T[])
    0x286FAFEA: vm_assert("neq", "bool[]"),
    0x62C6F9FB: vm_assert("neq", "bool[]", log=True),
    0x56F29CBA: vm_assert("neq", "uint256[]"),
    0x9A7FBD8F: vm_assert("neq", "uint256[]", log=True),
    0x0B72F4EF: vm_assert("neq", "int256[]"),
    0xD3977322: vm_assert("neq", "int256[]", log=True),
    0x46D0B252: vm_assert("neq", "address[]"),
    0x72C7E0B5: vm_assert("neq", "address[]", log=True),
    0x0603EA68: vm_assert("neq", "bytes32[]"),
    0xB873634C: vm_assert("neq", "bytes32[]", log=True),
    0xBDFACBE8: vm_assert("neq", "string[]"),
    0xB67187F3: vm_assert("neq", "string[]", log=True),
    0xEDECD035: vm_assert("neq", "bytes[]"),
    0x1DCD1F68: vm_assert("neq", "bytes[]", log=True),
    # assertLt/Gt/Le/Ge
    0xB12FC005: vm_assert("ult", "uint256"),
    0x65D5C135: vm_assert("ult", "uint256", log=True),
    0x3E914080: vm_assert("slt", "int256"),
    0x9FF531E3: vm_assert("slt", "int256", log=True),
    0xDB07FCD2: vm_assert("ugt", "uint256"),
    0xD9A3C4D2: vm_assert("ugt", "uint256", log=True),
    0x5A362D45: vm_assert("sgt", "int256"),
    0xF8D33B9B: vm_assert("sgt", "int256", log=True),
    0x8466F415: vm_assert("ule", "uint256"),
    0xD17D4B0D: vm_assert("ule", "uint256", log=True),
    0x95FD154E: vm_assert("sle", "int256"),
    0x4DFE692C: vm_assert("sle", "int256", log=True),
    0xA8D4D1D9: vm_assert("uge", "uint256"),
    0xE25242C0: vm_assert("uge", "uint256", log=True),
    0x0A30B771: vm_assert("sge", "int256"),
    0xA84328DD: vm_assert("sge", "int256", log=True),
}
