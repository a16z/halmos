// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

//
// Example from ItyFuzz paper (Figure 2): https://arxiv.org/pdf/2306.17135
//

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

contract SimpleStateTest is SymTest, Test {
    SimpleState target;

    function setUp() public {
        target = new SimpleState();
    }

    function check_buggy() public {
        bool success;

        // note: a total of 253 feasible paths are generated, of which only 10 unique states exist
        for (uint i = 0; i < 10; i++) {
            (success,) = address(target).call(svm.createCalldata("SimpleState"));
            vm.assume(success);
        }

        assertFalse(target.buggy());
    }
}
