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

contract PanicTest is Test {
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

    /// @custom:halmos --panic-error-codes 0x05
    function check_panic_5_fail_old(bool x) public {
        if (x) _panic_old_compiler(5);
    }

    /// @custom:halmos --panic-error-codes 0x11
    function check_panic_11_fail(uint x) public returns (uint) {
        // 0x11: overflow
        return x + 1; // counterexample: x == 2^256 - 1
    }

    function check_panic_11_pass(uint x) public returns (uint) {
        return x + 1;
    }

    /// @custom:halmos --panic-error-codes 0x12
    function check_panic_12_fail(uint x) public returns (uint) {
        // 0x12: div-by-zero
        return 10 / x; // counterexample: x == 0
    }

    function check_panic_12_pass(uint x) public returns (uint) {
        return 10 / x;
    }
}
