// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract C {
    uint public num;

    function inc(uint x) public {
        require(x <= 2);
        num += x;
    }
}

contract InvariantTest is Test {
    C c;

    function setUp() public {
        c = new C();
    }

    function invariant_max() public {
        console.log(c.num());
        assertLe(c.num(), 4);
    //  assert(c.num() != 3);
    }
}
