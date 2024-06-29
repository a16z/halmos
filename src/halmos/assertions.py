# SPDX-License-Identifier: AGPL-3.0

from z3 import *

from .utils import *


def assertTrue(arg):
    return test(uint256(arg.get_word(4)), True)


def assertFalse(arg):
    return test(uint256(arg.get_word(4)), False)


def assertEq_uint_uint(arg):
    v1 = uint256(arg.get_word(4))
    v2 = uint256(arg.get_word(36))
    return v1 == v2


def assertNotEq_uint_uint(arg):
    v1 = uint256(arg.get_word(4))
    v2 = uint256(arg.get_word(36))
    return v1 != v2


def assertLt_uint_uint(arg):
    v1 = uint256(arg.get_word(4))
    v2 = uint256(arg.get_word(36))
    return ULT(v1, v2)


def assertLt_int_int(arg):
    v1 = uint256(arg.get_word(4))
    v2 = uint256(arg.get_word(36))
    return v1 < v2


def assertGt_uint_uint(arg):
    v1 = uint256(arg.get_word(4))
    v2 = uint256(arg.get_word(36))
    return UGT(v1, v2)


def assertGt_int_int(arg):
    v1 = uint256(arg.get_word(4))
    v2 = uint256(arg.get_word(36))
    return v1 > v2


def assertLe_uint_uint(arg):
    v1 = uint256(arg.get_word(4))
    v2 = uint256(arg.get_word(36))
    return ULE(v1, v2)


def assertLe_int_int(arg):
    v1 = uint256(arg.get_word(4))
    v2 = uint256(arg.get_word(36))
    return v1 <= v2


def assertGe_uint_uint(arg):
    v1 = uint256(arg.get_word(4))
    v2 = uint256(arg.get_word(36))
    return UGE(v1, v2)


def assertGe_int_int(arg):
    v1 = uint256(arg.get_word(4))
    v2 = uint256(arg.get_word(36))
    return v1 >= v2


assert_cheatcode_handler = {
    0x0C9FD581: assertTrue,  # assertTrue_bool,
    0xA34EDC03: assertTrue,  # assertTrue_bool_string,
    0xA5982885: assertFalse,  # assertFalse_bool,
    0x7BA04809: assertFalse,  # assertFalse_bool_string,
    # assertEq(T, T)
    0xF7FE3477: assertEq_uint_uint,  # assertEq_bool_bool,
    0x4DB19E7E: assertEq_uint_uint,  # assertEq_bool_bool_string,
    0x98296C54: assertEq_uint_uint,  # assertEq_uint256_uint256,
    0x88B44C85: assertEq_uint_uint,  # assertEq_uint256_uint256_string,
    0xFE74F05B: assertEq_uint_uint,  # assertEq_int256_int256,
    0x714A2F13: assertEq_uint_uint,  # assertEq_int256_int256_string,
    0x515361F6: assertEq_uint_uint,  # assertEq_address_address,
    0x2F2769D1: assertEq_uint_uint,  # assertEq_address_address_string,
    0x7C84C69B: assertEq_uint_uint,  # assertEq_bytes32_bytes32,
    0xC1FA1ED0: assertEq_uint_uint,  # assertEq_bytes32_bytes32_string,
    # 0xF320D963: assertEq_string_string,
    # 0x36F656D8: assertEq_string_string_string,
    # 0x97624631: assertEq_bytes_bytes,
    # 0xE24FED00: assertEq_bytes_bytes_string,
    # assertEq(T[], T[])
    # 0x707DF785: assertEq_bool_array_bool_array,
    # 0xE48A8F8D: assertEq_bool_array_bool_array_string,
    # 0x975D5A12: assertEq_uint256_array_uint256_array,
    # 0x5D18C73A: assertEq_uint256_array_uint256_array_string,
    # 0x711043AC: assertEq_int256_array_int256_array,
    # 0x191F1B30: assertEq_int256_array_int256_array_string,
    # 0x3868AC34: assertEq_address_array_address_array,
    # 0x3E9173C5: assertEq_address_array_address_array_string,
    # 0x0CC9EE84: assertEq_bytes32_array_bytes32_array,
    # 0xE03E9177: assertEq_bytes32_array_bytes32_array_string,
    # 0xCF1C049C: assertEq_string_array_string_array,
    # 0xEFF6B27D: assertEq_string_array_string_array_string,
    # 0xE5FB9B4A: assertEq_bytes_array_bytes_array,
    # 0xF413F0B6: assertEq_bytes_array_bytes_array_string,
    # assertNotEq(T, T)
    0x236E4D66: assertNotEq_uint_uint,  # assertNotEq_bool_bool,
    0x1091A261: assertNotEq_uint_uint,  # assertNotEq_bool_bool_string,
    0xB7909320: assertNotEq_uint_uint,  # assertNotEq_uint256_uint256,
    0x98F9BDBD: assertNotEq_uint_uint,  # assertNotEq_uint256_uint256_string,
    0xF4C004E3: assertNotEq_uint_uint,  # assertNotEq_int256_int256,
    0x4724C5B9: assertNotEq_uint_uint,  # assertNotEq_int256_int256_string,
    0xB12E1694: assertNotEq_uint_uint,  # assertNotEq_address_address,
    0x8775A591: assertNotEq_uint_uint,  # assertNotEq_address_address_string,
    0x898E83FC: assertNotEq_uint_uint,  # assertNotEq_bytes32_bytes32,
    0xB2332F51: assertNotEq_uint_uint,  # assertNotEq_bytes32_bytes32_string,
    # 0x6A8237B3: assertNotEq_string_string,
    # 0x78BDCEA7: assertNotEq_string_string_string,
    # 0x9507540E: assertNotEq_bytes_bytes_string,
    # 0x3CF78E28: assertNotEq_bytes_bytes,
    # assertNotEq(T[], T[])
    # 0x286FAFEA: assertNotEq_bool_array_bool_array,
    # 0x62C6F9FB: assertNotEq_bool_array_bool_array_string,
    # 0x56F29CBA: assertNotEq_uint256_array_uint256_array,
    # 0x9A7FBD8F: assertNotEq_uint256_array_uint256_array_string,
    # 0x0B72F4EF: assertNotEq_int256_array_int256_array,
    # 0xD3977322: assertNotEq_int256_array_int256_array_string,
    # 0x46D0B252: assertNotEq_address_array_address_array,
    # 0x72C7E0B5: assertNotEq_address_array_address_array_string,
    # 0x0603EA68: assertNotEq_bytes32_array_bytes32_array,
    # 0xB873634C: assertNotEq_bytes32_array_bytes32_array_string,
    # 0xBDFACBE8: assertNotEq_string_array_string_array,
    # 0xB67187F3: assertNotEq_string_array_string_array_string,
    # 0xEDECD035: assertNotEq_bytes_array_bytes_array,
    # 0x1DCD1F68: assertNotEq_bytes_array_bytes_array_string,
    # assertLt/Gt/Le/Ge
    0xB12FC005: assertLt_uint_uint,  # assertLt_uint256_uint256,
    0x65D5C135: assertLt_uint_uint,  # assertLt_uint256_uint256_string,
    0x3E914080: assertLt_int_int,  # assertLt_int256_int256,
    0x9FF531E3: assertLt_int_int,  # assertLt_int256_int256_string,
    0xDB07FCD2: assertGt_uint_uint,  # assertGt_uint256_uint256,
    0xD9A3C4D2: assertGt_uint_uint,  # assertGt_uint256_uint256_string,
    0x5A362D45: assertGt_int_int,  # assertGt_int256_int256,
    0xF8D33B9B: assertGt_int_int,  # assertGt_int256_int256_string,
    0x8466F415: assertLe_uint_uint,  # assertLe_uint256_uint256,
    0xD17D4B0D: assertLe_uint_uint,  # assertLe_uint256_uint256_string,
    0x95FD154E: assertLe_int_int,  # assertLe_int256_int256,
    0x4DFE692C: assertLe_int_int,  # assertLe_int256_int256_string,
    0xA8D4D1D9: assertGe_uint_uint,  # assertGe_uint256_uint256,
    0xE25242C0: assertGe_uint_uint,  # assertGe_uint256_uint256_string,
    0x0A30B771: assertGe_int_int,  # assertGe_int256_int256,
    0xA84328DD: assertGe_int_int,  # assertGe_int256_int256_string,
}
