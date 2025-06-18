// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

// from ItyFuzz paper (Figure 2): https://arxiv.org/pdf/2306.17135

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

uint256 constant N = 5;

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
        return counter == N;
    }
}

contract SimpleStateTest is SymTest, Test {
    SimpleState target;

    function setUp() public {
        target = new SimpleState();
    }

    function check_buggy_excluding_view() public {
        bool success;

        for (uint i = 0; i < N; i++) {
            (success,) = address(target).call(svm.createCalldata("SimpleState")); // excluding view functions
            vm.assume(success);
        }

        assertFalse(target.buggy());
    }

    function check_buggy_with_storage_snapshot() public {
        bool success;

        // take the initial storage snapshot
        uint prev = svm.snapshotStorage(address(target));

        for (uint i = 0; i < N; i++) {
            (success,) = address(target).call(svm.createCalldata("SimpleState", true)); // including view functions
            vm.assume(success);

            // ignore if no storage changes
            uint curr = svm.snapshotStorage(address(target));
            vm.assume(curr != prev);
            prev = curr;
        }

        assertFalse(target.buggy());
    }

    function check_buggy_with_state_snapshot() public {
        bool success;

        // take the initial state snapshot
        uint prev = vm.snapshotState();

        for (uint i = 0; i < N; i++) {
            (success,) = address(target).call(svm.createCalldata("SimpleState", true)); // including view functions
            vm.assume(success);

            // ignore if no state changes
            uint curr = vm.snapshotState();
            vm.assume(curr != prev);
            prev = curr;
        }

        assertFalse(target.buggy());
    }
}
