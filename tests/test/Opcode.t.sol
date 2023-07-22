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

    function check_SIGNEXTEND(uint value) public {
        _check_SIGNEXTEND(0, value);
        _check_SIGNEXTEND(1, value);
        _check_SIGNEXTEND(2, value);
        _check_SIGNEXTEND(30, value);
        _check_SIGNEXTEND(31, value);
        _check_SIGNEXTEND(32, value);
        _check_SIGNEXTEND(33, value);
    }

    /* TODO: support symbolic size
    function check_SIGNEXTEND(uint size, uint value) public {
        _check_SIGNEXTEND(size, value);
    }
    */

    function _check_SIGNEXTEND(uint size, uint value) public {
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

    function check_PUSH0() public {
        // target bytecode is 0x365f5f37365ff3
        //  36 CALLDATASIZE
        //  5F PUSH0
        //  5F PUSH0
        //  37 CALLDATACOPY -> copies calldata at mem[0..calldatasize]

        //  36 CALLDATASIZE
        //  5F PUSH0
        //  F3 RETURN -> returns mem[0..calldatasize]

        // a tiny deployer (that uses PUSH0), to deploy the above bytecode
        uint256 deployCode = 0x66365f5f37365ff35f5260076019f3;
        address target;
        assembly {
            mstore(0, deployCode)
            target := create(/* value */ 0, /* offset */ 0x11, /* size */ 15)
        }

        (bool success, bytes memory result) = target.call(bytes("hello PUSH0"));
        assertTrue(success);
        assertEq(string(result), "hello PUSH0");
    }
}
