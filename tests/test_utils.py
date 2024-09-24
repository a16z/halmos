from z3 import (
    ULE,
    BitVec,
    BitVecSort,
    BitVecVal,
    Function,
    Not,
    simplify,
)

from halmos.utils import f_sha3_256_name, match_dynamic_array_overflow_condition


def test_match_dynamic_array_overflow_condition():
    # Create Z3 objects
    f_sha3_256 = Function(f_sha3_256_name, BitVecSort(256), BitVecSort(256))
    slot = BitVec("slot", 256)
    offset = BitVecVal(1000, 256)  # Less than 2**64

    # Test the function
    cond = Not(ULE(f_sha3_256(slot), offset + f_sha3_256(slot)))
    assert match_dynamic_array_overflow_condition(cond)

    # Test with opposite order of addition
    opposite_order_cond = Not(ULE(f_sha3_256(slot), f_sha3_256(slot) + offset))
    assert not match_dynamic_array_overflow_condition(opposite_order_cond)

    # Test with opposite order after simplification
    simplified_opposite_order_cond = simplify(
        Not(ULE(f_sha3_256(slot), f_sha3_256(slot) + offset))
    )
    assert match_dynamic_array_overflow_condition(simplified_opposite_order_cond)

    # Test with offset = 2**64 - 1 (should match)
    max_valid_offset = BitVecVal(2**64 - 1, 256)
    max_valid_cond = Not(ULE(f_sha3_256(slot), max_valid_offset + f_sha3_256(slot)))
    assert match_dynamic_array_overflow_condition(max_valid_cond)

    # Test with offset >= 2**64
    large_offset = BitVecVal(2**64, 256)
    large_offset_cond = Not(ULE(f_sha3_256(slot), large_offset + f_sha3_256(slot)))
    assert not match_dynamic_array_overflow_condition(large_offset_cond)

    # Test with a different function
    different_func = Function("different_func", BitVecSort(256), BitVecSort(256))
    non_matching_cond = Not(ULE(different_func(slot), offset + different_func(slot)))
    assert not match_dynamic_array_overflow_condition(non_matching_cond)

    # Test with just ULE, not Not(ULE(...))
    ule_only = ULE(f_sha3_256(slot), offset + f_sha3_256(slot))
    assert not match_dynamic_array_overflow_condition(ule_only)

    # Test with mismatched slots
    slot2 = BitVec("slot2", 256)
    mismatched_slots = Not(ULE(f_sha3_256(slot), offset + f_sha3_256(slot2)))
    assert not match_dynamic_array_overflow_condition(mismatched_slots)
