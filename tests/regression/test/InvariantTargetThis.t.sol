// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import "forge-std/Test.sol";

contract InvariantTargetBase {
    bool public setUp_called;
    bool public foo_called;
    bool public _invariant_this_called;
    bool public test_foo_called;
    bool public check_foo_called;
    bool public setUpSymbolic_called;
    bool public afterInvariant_called;

    function setUp() public virtual {
        setUp_called = true;
    }

    function test_foo() public {
        test_foo_called = true;
    }

    function check_foo() public {
        check_foo_called = true;
    }

    function invariant_this() public {
        _invariant_this_called = true;
    }

    function afterInvariant() public {
        afterInvariant_called = true;
    }

    // should be included
    function foo() public {
        foo_called = true;
    }
}

// https://github.com/a16z/halmos/issues/514
// special functions like test_, check_, setUp(), invariant_, etc.
// should not be considered as targets when selecting targetContract(address(this))

// FIXME: this test generates 1 model with the solidity storage layout, but 2 models (at depth 2)
//        with the generic storage layout, so we set depth to 1 for consistent results
/// @custom:halmos --invariant-depth 1
contract InvariantTargetThis is InvariantTargetBase, Test {
    // not a test contract, but deployed by the test contract
    // so it should be included, and its target functions included even if they
    // use "reserved" names (e.g. test_, check_, setUp, invariant_, etc.)
    InvariantTargetBase public inception;

    // should be excluded
    function setUp() public override {
        assertFalse(setUp_called);
        setUp_called = true;

        inception = new InvariantTargetBase();

        targetContract(address(this));
        targetContract(address(inception));
    }

    function invariant_targets_special_functions_excluded() public view {
        assertEq(setUp_called, true);
        assertEq(check_foo_called, false);
        assertEq(setUpSymbolic_called, false);
        assertEq(test_foo_called, false);
        assertEq(_invariant_this_called, false);
        assertEq(afterInvariant_called, false);
    }

    // we expect a counterexample, showing that setUp is called
    function invariant_targets_inception_setUp_included() public view {
        assertEq(inception.setUp_called(), false);
    }

    // we expect a counterexample, showing that invariant_this is called
    function invariant_targets_inception_invariant_included() public view {
        assertEq(inception._invariant_this_called(), false);
    }

    // we expect a counterexample, showing that test_foo is called
    function invariant_targets_inception_test_included() public view {
        assertEq(inception.test_foo_called(), false);
    }

    // we expect a counterexample, showing that check_foo is called
    function invariant_targets_inception_check_included() public view {
        assertEq(inception.check_foo_called(), false);
    }

    // we expect a counterexample, showing that afterInvariant is called
    function invariant_targets_inception_afterInvariant_included() public view {
        assertEq(inception.afterInvariant_called(), false);
    }

    // we expect a counterexample, showing that foo is indeed called
    function invariant_targets_foo_included() public view {
        assertEq(foo_called, false);
    }
}
