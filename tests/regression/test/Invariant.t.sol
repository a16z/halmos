// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract C is Test {
    uint public num;

    function inc() public {
        num++;
    }
}

contract InvariantTest is Test {
    C c;

    function setUp() public {
        c = new C();
    }

    function invariant_positive() public {
        assertGe(c.num(), 0);
    }
}
