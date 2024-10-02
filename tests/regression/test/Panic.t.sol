// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

/*
 *  Panic error code:
 *  https://docs.soliditylang.org/en/latest/control-structures.html#panic-via-assert-and-error-via-require
 *  - 0x00: Used for generic compiler inserted panics.
 *  - 0x01: If you call assert with an argument that evaluates to false.
 *  - 0x11: If an arithmetic operation results in underflow or overflow outside of an unchecked { ... } block.
 *  - 0x12; If you divide or modulo by zero (e.g. 5 / 0 or 23 % 0).
 *  - 0x21: If you convert a value that is too big or negative into an enum type.
 *  - 0x22: If you access a storage byte array that is incorrectly encoded.
 *  - 0x31: If you call .pop() on an empty array.
 *  - 0x32: If you access an array, bytesN or an array slice at an out-of-bounds or negative index (i.e. x[i] where i >= x.length or i < 0).
 *  - 0x41: If you allocate too much memory or create an array that is too large.
 *  - 0x51: If you call a zero-initialized variable of internal function type.
 */

contract C {
    function inc(uint x) public returns (uint) {
        return x + 1;
    }
}

contract PanicTest is Test {
    C c = new C();

    function _panic(uint code) internal pure {
        // revert Panic(code);
        bytes memory data = abi.encodeWithSignature("Panic(uint256)", code);
        assembly {
            revert(add(data, 0x20), mload(data))
        }
    }

    function _panic_old_compiler(uint code) internal pure {
        assembly {
            mstore(0x00, 0x4e487b71)
            mstore(0x20, code)
            revert(0x1c, 0x24)
        }
    }

    /// @custom:halmos --panic-error-codes 0x00
    function check_panic_0_fail(bool x) public {
        if (x) _panic(0);
    }

    function check_panic_0_pass(bool x) public {
        if (x) _panic(0); // not treated as failure because the default error code is 1
    }

    function check_panic_1_fail(bool x) public {
        if (x) _panic(1); // default error code is 1
    }

    /// @custom:halmos --panic-error-codes 0x00
    function check_panic_1_pass(bool x) public {
        if (x) _panic(1);
    }

    //
    // multiple error codes
    //

    /// @custom:halmos --panic-error-codes 0x02,0x03
    function check_panic_2_or_3_fail_2(bool x) public {
        if (x) _panic(2);
    }

    /// @custom:halmos --panic-error-codes 0x02,0x03
    function check_panic_2_or_3_fail_3(bool x) public {
        if (x) _panic(3);
    }

    /// @custom:halmos --panic-error-codes *
    function check_panic_any_fail_4(bool x) public {
        if (x) _panic(4);
    }

    //
    // old compiler revert
    //

    /// @custom:halmos --panic-error-codes 0x05
    function check_panic_5_fail_old(bool x) public {
        if (x) _panic_old_compiler(5);
    }

    //
    // numeric literal bases
    //

    // binary
    /// @custom:halmos --panic-error-codes 0b111
    function check_panic_7_fail(bool x) public {
        if (x) _panic(7);
    }

    // octal
    /// @custom:halmos --panic-error-codes 0o10
    function check_panic_8_fail(bool x) public {
        if (x) _panic(8);
    }

    // decimal
    /// @custom:halmos --panic-error-codes 10
    function check_panic_10_fail(bool x) public {
        if (x) _panic(10);
    }

    // hex
    /// @custom:halmos --panic-error-codes 0x10
    function check_panic_16_fail(bool x) public {
        if (x) _panic(16);
    }

    //
    // panic error code semantics
    //

    /// @custom:halmos --panic-error-codes 0x11
    function check_panic_0x11_fail(uint x) public returns (uint) {
        // 0x11: overflow
        return x + 1; // counterexample: x == 2^256 - 1
    }

    function check_panic_0x11_pass(uint x) public returns (uint) {
        return x + 1;
    }

    /// @custom:halmos --panic-error-codes 0x12
    function check_panic_0x12_fail(uint x) public returns (uint) {
        // 0x12: div-by-zero
        return 10 / x; // counterexample: x == 0
    }

    function check_panic_0x12_pass(uint x) public returns (uint) {
        return 10 / x;
    }

    //
    // panic propagation
    //

    /// @custom:halmos --panic-error-codes 0x11
    function check_panic_inc_fail(uint x) public returns (uint) {
        // 0x11: overflow
        return c.inc(x); // counterexample: x == 2^256 - 1
    }

    //
    // capturing different types of reverts
    //

    /// @custom:halmos --panic-error-codes 0x11
    function check_panic_inc_overflow_fail(uint x) public returns (uint) {
        // fail due to overflow, Panic(0x11)
        // but no assertion violation
        assert(x + 1 > x); // counterexample: x == 2^256 - 1
    }

    function check_panic_inc_overflow_pass(uint x) public returns (uint) {
        // pass because the overflow path is silently ignored, then the assertion holds for non-overflow paths
        assert(x + 1 > x); // pass; overflow ignored
    }

    function check_panic_inc_assert_fail(uint x) public returns (uint) {
        // fail due to assertion failure, Panic(0x01)
        // but no overflow
        unchecked {
            assert(x + 1 > x); // counterexample: x == 2^256 - 1
        }
    }

    /// @custom:halmos --panic-error-codes 0x11
    function check_panic_inc_assert_pass(uint x) public returns (uint) {
        // pass because the assertion violation error code is ignored, and there's no overflow
        unchecked {
            assert(x + 1 > x); // pass, assertion violation ignored
        }
    }

    /// @custom:halmos --panic-error-codes 0xff
    function check_panic_inc_cheatcode_fail(uint x) public returns (uint) {
        // fail even if Panic(1) is ignored,
        // because assertion cheatcode failures are handled separately and are always captured
        unchecked {
            assertGt(x + 1, x); // counterexample: x == 2^256 - 1
        }
    }
}
