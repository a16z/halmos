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
    function checkFail_setUp() public {
        assertEq(create.value(), 0);
    }
    */

    function check_set(uint x) public {
        create.set(x);
        assertEq(create.value(), x);
    }

    function check_immutable() public {
        assertEq(create.halmos(), 0x220E);
    }

    function check_initialized() public {
        assertEq(create.initialized(), 7);
    }

    function check_const() public {
        assertEq(create.const(), 11);
    }
}
