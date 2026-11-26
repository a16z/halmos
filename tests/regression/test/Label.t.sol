// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract LabelTarget {
    address public owner;

    constructor(address _owner) {
        owner = _owner;
    }
}

/// vm.label and vm.getLabel (halmos#447): labels annotate the addresses of counterexamples
contract LabelTest is Test, SymTest {
    LabelTarget target;
    address alice;

    function setUp() public {
        alice = address(0xA11CE);
        vm.label(alice, "alice");
        target = new LabelTarget(alice);
        vm.label(address(target), "target");
    }

    function check_getLabel() public {
        assertEq(vm.getLabel(alice), "alice");
        assertEq(vm.getLabel(address(target)), "target");
        assertEq(vm.getLabel(address(0xB0B)), "unlabeled:0x0000000000000000000000000000000000000B0b");

        // the latest label wins
        vm.label(alice, "alice2");
        assertEq(vm.getLabel(alice), "alice2");
    }

    /// counterexample: user = alice, rendered `(alice)`
    function check_label_fail(address user) public view {
        assert(user != target.owner());
    }

    /// labels of symbolic addresses are resolved with the counterexample
    function check_symbolic_label_fail() public {
        address bob = svm.createAddress("bob");
        vm.label(bob, "bob");
        assert(bob != address(target));
    }
}
