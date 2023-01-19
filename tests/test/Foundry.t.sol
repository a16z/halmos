// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract FoundryTest is Test {
    function testFail() public {
        assertTrue(false);
    }

    function testAssume(uint x) public {
        vm.assume(x < 10);
        assertLt(x, 100);
    }
}
