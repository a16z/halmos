// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

library Opcode {
    function SIGNEXTEND(uint size, uint value) internal pure returns (uint result) {
        assembly {
            result := signextend(size, value)
        }
    }
}

contract OpcodeTest is Test {

    function test_SIGNEXTEND(uint value) public {
        _test_SIGNEXTEND(0, value);
        _test_SIGNEXTEND(1, value);
        _test_SIGNEXTEND(2, value);
        _test_SIGNEXTEND(30, value);
        _test_SIGNEXTEND(31, value);
        _test_SIGNEXTEND(32, value);
        _test_SIGNEXTEND(33, value);
    }

    /* TODO: support symbolic size
    function test_SIGNEXTEND(uint size, uint value) public {
        _test_SIGNEXTEND(size, value);
    }
    */

    function _test_SIGNEXTEND(uint size, uint value) public {
        uint result1 = Opcode.SIGNEXTEND(size, value);
        uint result2;
        if (size > 31) {
            result2 = value;
        } else {
            uint testbit = size * 8 + 7;
            uint signbit = (1 << testbit);
            if ((value & signbit) > 0) {
                result2 = value | (type(uint).max - signbit + 1);
            } else {
                result2 = value & (signbit - 1);
            }
        }
        assertEq(result1, result2);
    }

}
