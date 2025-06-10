// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";

// https://github.com/a16z/halmos/issues/514
// special functions like test_, check_, setUp(), invariant_, etc.
// should not be considered as targets when selecting targetContract(address(this))

// FIXME: this test generates 1 model with the solidity storage layout, but 2 models (at depth 2)
//        with the generic storage layout, so we set depth to 1 for consistent results
/// @custom:halmos --invariant-depth 1
contract InvariantTest is Test {
    bool setUp_called;
    bool foo_called;
    bool invariant_this_called;
    bool test_foo_called;
    bool check_foo_called;
    bool setUpSymbolic_called;

    // should be excluded
    function setUp() public {
        assertFalse(setUp_called);
        setUp_called = true;

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
