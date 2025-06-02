// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract SolverTest is SymTest, Test {
    uint[] numbers;

    function check_dynamic_array_overflow() public {
        numbers = new uint[](5); // shouldn't generate loop bounds warning
    }

    /// @custom:halmos --solver-timeout-assertion 1
    function check_too_many_open_files() public {
        // regression test for too many open files error: https://github.com/a16z/halmos/issues/523
        // this test simulates a situation where many solver processes are killed due to timeout.
        // if file descriptors are not properly closed, this test will fail with "Too many open files" error.
        if (svm.createBool("*")) { some_hard_query(); } else { some_hard_query(); }
        if (svm.createBool("*")) { some_hard_query(); } else { some_hard_query(); }
        if (svm.createBool("*")) { some_hard_query(); } else { some_hard_query(); }
        if (svm.createBool("*")) { some_hard_query(); } else { some_hard_query(); }
        if (svm.createBool("*")) { some_hard_query(); } else { some_hard_query(); }
        if (svm.createBool("*")) { some_hard_query(); } else { some_hard_query(); }
    }

    function some_hard_query() internal {
        uint a = svm.createUint256("a");
        uint b = svm.createUint256("b");
        uint c = svm.createUint256("c");
        uint n = svm.createUint256("n");

        vm.assume(n > 2);
        // we use a simple arithmetic constraint that is hard enough to solve within the 1ms timeout,
        // which is sufficient for testing that solver processes are properly killed and cleaned up.
        // note: we avoid exponentiation (a**n + b**n != c**n) as it creates too many execution paths at bytecode level.
        assertNotEq(a*n + b*n, c*n);
    }
}
