// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "forge-std/StdCheats.sol";

import "../src/Counter.sol";

contract FoundryTest is Test {
    /* TODO: support testFail prefix
    function testFail() public {
        assertTrue(false);
    }
    */

    function testAssume(uint x) public {
        vm.assume(x < 10);
        assertLt(x, 100);
    }

    function testGetCode(uint x) public {
        Counter counter = Counter(deployCode("./out/Counter.sol/Counter.json"));
        counter.set(x);
        assertEq(counter.cnt(), x);

        Counter counter2 = Counter(deployCode("Counter.sol:Counter"));
        counter2.set(x);
        assertEq(counter2.cnt(), x);
    }
}
