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

    # for eq and neq, the bitsize can be arbitrary, e.g., arrays

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

    # for comparison operators, the bitsize must be 256-bit

    if v1.size() != 256 or v2.size() != 256:
        raise ValueError(f"mk_cond: incompatible size: {v1} {bop} {v2}")

    if bop == "ult":
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


def mk_assert_handler(signature):
    start_idx = signature.index("assert") + len("assert")
    end_idx = signature.index("(")

    comparison = signature[start_idx:end_idx].strip()
    parameters = signature[end_idx:].strip("()")
    params_list = [param.strip() for param in parameters.split(",")]
    log = (len(params_list) > 2) and (params_list[-1] == "string")
    data_types = [param for param in params_list]

    if data_types:
        data_type = data_types[0]
    else:
        raise HalmosException(f"No data type found in signature: {signature}")

    # Calls vm_assert with the parsed values
    vm_assert(comparison, data_type, log)


signatures = {
    0x045C55CE: mk_assert_handler(
        "assertApproxEqAbsDecimal(uint256,uint256,uint256,uint256)"
    ),
    0x60429EB2: mk_assert_handler(
        "assertApproxEqAbsDecimal(uint256,uint256,uint256,uint256,string)"
    ),
    0x3D5BC8BC: mk_assert_handler(
        "assertApproxEqAbsDecimal(int256,int256,uint256,uint256)"
    ),
    0x6A5066D4: mk_assert_handler(
        "assertApproxEqAbsDecimal(int256,int256,uint256,uint256,string)"
    ),
    0x16D207C6: mk_assert_handler("assertApproxEqAbs(uint256,uint256,uint256)"),
    0xF710B062: mk_assert_handler(
        "assertApproxEqAbs(uint256,uint256,uint256,string)"
    ),
    0x240F839D: mk_assert_handler("assertApproxEqAbs(int256,int256,uint256)"),
    0x8289E621: mk_assert_handler(
        "assertApproxEqAbs(int256,int256,uint256,string)"
    ),
    0x21ED2977: mk_assert_handler(
        "assertApproxEqRelDecimal(uint256,uint256,uint256,uint256)"
    ),
    0x82D6C8FD: mk_assert_handler(
        "assertApproxEqRelDecimal(uint256,uint256,uint256,uint256,string)"
    ),
    0xABBF21CC: mk_assert_handler(
        "assertApproxEqRelDecimal(int256,int256,uint256,uint256)"
    ),
    0xFCCC11C4: mk_assert_handler(
        "assertApproxEqRelDecimal(int256,int256,uint256,uint256,string)"
    ),
    0x8CF25EF4: mk_assert_handler("assertApproxEqRel(uint256,uint256,uint256)"),
    0x1ECB7D33: mk_assert_handler(
        "assertApproxEqRel(uint256,uint256,uint256,string)"
    ),
    0xFEA2D14F: mk_assert_handler("assertApproxEqRel(int256,int256,uint256)"),
    0xEF277D72: mk_assert_handler(
        "assertApproxEqRel(int256,int256,uint256,string)"
    ),
    0x27AF7D9C: mk_assert_handler("assertEqDecimal(uint256,uint256,uint256)"),
    0xD0CBBDEF: mk_assert_handler(
        "assertEqDecimal(uint256,uint256,uint256,string)"
    ),
    0x48016C04: mk_assert_handler("assertEqDecimal(int256,int256,uint256)"),
    0x7E77B0C5: mk_assert_handler("assertEqDecimal(int256,int256,uint256,string)"),
    0xF7FE3477: mk_assert_handler("assertEq(bool,bool)"),
    0x4DB19E7E: mk_assert_handler("assertEq(bool,bool,string)"),
    0xF320D963: mk_assert_handler("assertEq(string,string)"),
    0x36F656D8: mk_assert_handler("assertEq(string,string,string)"),
    0x97624631: mk_assert_handler("assertEq(bytes,bytes)"),
    0xE24FED00: mk_assert_handler("assertEq(bytes,bytes,string)"),
    0x707DF785: mk_assert_handler("assertEq(bool[],bool[])"),
    0xE48A8F8D: mk_assert_handler("assertEq(bool[],bool[],string)"),
    0x975D5A12: mk_assert_handler("assertEq(uint256[],uint256[])"),
    0x5D18C73A: mk_assert_handler("assertEq(uint256[],uint256[],string)"),
    0x711043AC: mk_assert_handler("assertEq(int256[],int256[])"),
    0x191F1B30: mk_assert_handler("assertEq(int256[],int256[],string)"),
    0x98296C54: mk_assert_handler("assertEq(uint256,uint256)"),
    0x3868AC34: mk_assert_handler("assertEq(address[],address[])"),
    0x3E9173C5: mk_assert_handler("assertEq(address[],address[],string)"),
    0x0CC9EE84: mk_assert_handler("assertEq(bytes32[],bytes32[])"),
    0xE03E9177: mk_assert_handler("assertEq(bytes32[],bytes32[],string)"),
    0xCF1C049C: mk_assert_handler("assertEq(string[],string[])"),
    0xEFF6B27D: mk_assert_handler("assertEq(string[],string[],string)"),
    0xE5FB9B4A: mk_assert_handler("assertEq(bytes[],bytes[])"),
    0xF413F0B6: mk_assert_handler("assertEq(bytes[],bytes[],string)"),
    0x88B44C85: mk_assert_handler("assertEq(uint256,uint256,string)"),
    0xFE74F05B: mk_assert_handler("assertEq(int256,int256)"),
    0x714A2F13: mk_assert_handler("assertEq(int256,int256,string)"),
    0x515361F6: mk_assert_handler("assertEq(address,address)"),
    0x2F2769D1: mk_assert_handler("assertEq(address,address,string)"),
    0x7C84C69B: mk_assert_handler("assertEq(bytes32,bytes32)"),
    0xC1FA1ED0: mk_assert_handler("assertEq(bytes32,bytes32,string)"),
    0xA5982885: mk_assert_handler("assertFalse(bool)"),
    0x7BA04809: mk_assert_handler("assertFalse(bool,string)"),
    0x1DCD1F68: mk_assert_handler("assertNotEq(bytes[],bytes[],string)"),
    0x236E4D66: mk_assert_handler("assertNotEq(bool,bool)"),
    0xF4C004E3: mk_assert_handler("assertNotEq(int256,int256)"),
    0x8BFF9133: mk_assert_handler(
        "assertGeDecimal(uint256,uint256,uint256,string)"
    ),
    0xAA5CF788: mk_assert_handler("assertLeDecimal(int256,int256,uint256,string)"),
    0x33949F0B: mk_assert_handler(
        "assertNotEqDecimal(int256,int256,uint256,string)"
    ),
    0x3D1FE08A: mk_assert_handler("assertGeDecimal(uint256,uint256,uint256)"),
    0x286FAFEA: mk_assert_handler("assertNotEq(bool[],bool[])"),
    0x4DFE692C: mk_assert_handler("assertLe(int256,int256,string)"),
    0xA8D4D1D9: mk_assert_handler("assertGe(uint256,uint256)"),
    0x65D5C135: mk_assert_handler("assertLt(uint256,uint256,string)"),
    0x6A8237B3: mk_assert_handler("assertNotEq(string,string)"),
    0x78BDCEA7: mk_assert_handler("assertNotEq(string,string,string)"),
    0xE25242C0: mk_assert_handler("assertGe(uint256,uint256,string)"),
    0x9FF531E3: mk_assert_handler("assertLt(int256,int256,string)"),
    0xD9A3C4D2: mk_assert_handler("assertGt(uint256,uint256,string)"),
    0x64949A8D: mk_assert_handler(
        "assertGtDecimal(uint256,uint256,uint256,string)"
    ),
    0x5A362D45: mk_assert_handler("assertGt(int256,int256)"),
    0xC304AAB7: mk_assert_handler("assertLeDecimal(uint256,uint256,uint256)"),
    0x78611F0E: mk_assert_handler("assertGtDecimal(int256,int256,uint256)"),
    0x0C9FD581: mk_assert_handler("assertTrue(bool)"),
    0xA84328DD: mk_assert_handler("assertGe(int256,int256,string)"),
    0xDB07FCD2: mk_assert_handler("assertGt(uint256,uint256)"),
    0x14E75680: mk_assert_handler("assertNotEqDecimal(int256,int256,uint256)"),
    0xB873634C: mk_assert_handler("assertNotEq(bytes32[],bytes32[],string)"),
    0x04A5C7AB: mk_assert_handler("assertGtDecimal(int256,int256,uint256,string)"),
    0xEDECD035: mk_assert_handler("assertNotEq(bytes[],bytes[])"),
    0xD3977322: mk_assert_handler("assertNotEq(int256[],int256[],string)"),
    0x46D0B252: mk_assert_handler("assertNotEq(address[],address[])"),
    0xECCDA437: mk_assert_handler("assertGtDecimal(uint256,uint256,uint256)"),
    0x5DF93C9B: mk_assert_handler("assertGeDecimal(int256,int256,uint256,string)"),
    0xBDFACBE8: mk_assert_handler("assertNotEq(string[],string[])"),
    0x72C7E0B5: mk_assert_handler("assertNotEq(address[],address[],string)"),
    0xA34EDC03: mk_assert_handler("assertTrue(bool,string)"),
    0xDC28C0F1: mk_assert_handler("assertGeDecimal(int256,int256,uint256)"),
    0xA972D037: mk_assert_handler(
        "assertLtDecimal(uint256,uint256,uint256,string)"
    ),
    0xF5A55558: mk_assert_handler(
        "assertNotEqDecimal(uint256,uint256,uint256,string)"
    ),
    0xB7909320: mk_assert_handler("assertNotEq(uint256,uint256)"),
    0xB2332F51: mk_assert_handler("assertNotEq(bytes32,bytes32,string)"),
    0xD17D4B0D: mk_assert_handler("assertLe(uint256,uint256,string)"),
    0x9507540E: mk_assert_handler("assertNotEq(bytes,bytes,string)"),
    0x898E83FC: mk_assert_handler("assertNotEq(bytes32,bytes32)"),
    0x0A30B771: mk_assert_handler("assertGe(int256,int256)"),
    0xB12E1694: mk_assert_handler("assertNotEq(address,address)"),
    0xB67187F3: mk_assert_handler("assertNotEq(string[],string[],string)"),
    0x8466F415: mk_assert_handler("assertLe(uint256,uint256)"),
    0xF8D33B9B: mk_assert_handler("assertGt(int256,int256,string)"),
    0x62C6F9FB: mk_assert_handler("assertNotEq(bool[],bool[],string)"),
    0x3CF78E28: mk_assert_handler("assertNotEq(bytes,bytes)"),
    0x2077337E: mk_assert_handler("assertLtDecimal(uint256,uint256,uint256)"),
    0x1091A261: mk_assert_handler("assertNotEq(bool,bool,string)"),
    0x3E914080: mk_assert_handler("assertLt(int256,int256)"),
    0x98F9BDBD: mk_assert_handler("assertNotEq(uint256,uint256,string)"),
    0x9A7FBD8F: mk_assert_handler("assertNotEq(uint256[],uint256[],string)"),
    0x8775A591: mk_assert_handler("assertNotEq(address,address,string)"),
    0x4724C5B9: mk_assert_handler("assertNotEq(int256,int256,string)"),
    0x7FEFBBE0: mk_assert_handler(
        "assertLeDecimal(uint256,uint256,uint256,string)"
    ),
    0xDBE8D88B: mk_assert_handler("assertLtDecimal(int256,int256,uint256)"),
    0x0B72F4EF: mk_assert_handler("assertNotEq(int256[],int256[])"),
    0x11D1364A: mk_assert_handler("assertLeDecimal(int256,int256,uint256)"),
    0x0603EA68: mk_assert_handler("assertNotEq(bytes32[],bytes32[])"),
    0xB12FC005: mk_assert_handler("assertLt(uint256,uint256)"),
    0x669EFCA7: mk_assert_handler("assertNotEqDecimal(uint256,uint256,uint256)"),
    0x95FD154E: mk_assert_handler("assertLe(int256,int256)"),
    0x56F29CBA: mk_assert_handler("assertNotEq(uint256[],uint256[])"),
    0x40F0B4E0: mk_assert_handler("assertLtDecimal(int256,int256,uint256,string)"),
}


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
