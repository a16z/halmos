// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract SetupSymbolicTest {
    function setUpSymbolic(uint x) public pure {
        if (x > 0) revert(); // generate multiple setup output states, but only a single success output state
    }

    function check_True() public pure {
        assert(true); // ensure setUp succeeds
    }
}
