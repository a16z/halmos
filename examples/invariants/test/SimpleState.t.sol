// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

// from ItyFuzz paper (Figure 2): https://arxiv.org/pdf/2306.17135

import "forge-std/Test.sol";

contract SimpleState {
    uint counter = 0;

    function incr(uint x) public {
        require(x <= counter);
        counter += 1;
    }

    function decr(uint x) public {
        require(x >= counter);
        counter -= 1;
    }

    function buggy() public view returns (bool) {
        return counter == 10;
    }
}

contract SimpleStateTest is Test {
    SimpleState target;

    function setUp() public {
        target = new SimpleState();
    }

    /// @custom:halmos --invariant-depth 10
    function invariant_buggy() public view {
        assertFalse(target.buggy());
    }
}
