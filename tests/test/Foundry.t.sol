// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "forge-std/StdCheats.sol";

import "../src/Counter.sol";

contract FoundryTest is Test {
    function testFail() public {
        assertTrue(false);
    }

    function testAssume(uint x) public {
        vm.assume(x < 10);
        assertLt(x, 100);
    }

    function testGetCode(uint x) public {
        Counter counter = Counter(deployCode("./out/Counter.sol/Counter.json"));

        assertEq(x, x);
    }

    function testPrank(address x) public {
        vm.prank(x); // not supported
    }
}
