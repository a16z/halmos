// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";

// https://github.com/a16z/halmos/issues/514
// special functions like test_, check_, setUp(), invariant_, etc.
// should not be considered as targets when selecting targetContract(address(this))
contract InvariantTest is Test {
    bool foo_called;
    bool invariant_this_called;
    bool test_foo_called;
    bool check_foo_called;
    bool setUpSymbolic_called;

    // should be excluded
    function setUp() public {
        targetContract(address(this));
    }

    // should be excluded
    function test_foo() public {
        test_foo_called = true;
    }

    // should be excluded
    function check_foo() public {
        check_foo_called = true;
    }

    // should be excluded
    function invariant_this() public {
        invariant_this_called = true;
    }

    // should be included
    function foo() public {
        foo_called = true;
    }

    function invariant_targets_special_functions_excluded() public view {
        assertEq(check_foo_called, false);
        assertEq(setUpSymbolic_called, false);
        assertEq(test_foo_called, false);
        assertEq(invariant_this_called, false);
    }

    // we expect a counterexample, showing that foo is indeed called
    function invariant_targets_foo_included() public view {
        assertEq(foo_called, false);
    }
}
