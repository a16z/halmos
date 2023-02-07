// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/Create.sol";

contract CreateTest is Test {
    Create public create;

    function setUp() public {
        create = new Create(0x220E);
    }

    function testSet(uint x) public {
        create.set(x);
        assertEq(create.value(), x);
        assertEq(create.halmos(), 0x220E);
    }
}
