// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/Create.sol";

contract CreateTest is Test {
    Create public create;

    function setUp() public {
        create = new Create(0x220E);
    }

    /* TODO: support checkFail prefix
    function checkFailSetUp() public {
        assertEq(create.value(), 0);
    }
    */

    function checkSet(uint x) public {
        create.set(x);
        assertEq(create.value(), x);
    }

    function checkImmutable() public {
        assertEq(create.halmos(), 0x220E);
    }

    function checkInitialized() public {
        assertEq(create.initialized(), 7);
    }

    function checkConst() public {
        assertEq(create.const(), 11);
    }
}
