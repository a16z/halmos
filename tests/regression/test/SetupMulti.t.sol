// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract Vault {
    uint256 public fee;
    bool public paused;

    constructor(uint256 _fee, bool _paused) {
        fee = _fee;
        paused = _paused;
    }

    function setFee(uint256 _fee) external {
        require(!paused, "paused");
        require(_fee <= 1000, "fee too high");
        fee = _fee;
    }
}

/// @dev regression tests for halmos issue #186: setUp() with several paths
/// used to fail with "Multiple paths were found in setUp()"
contract SetupMultiTest is Test, SymTest {
    Vault vault;
    uint256 mode;

    function setUp() public {
        // symbolic branching in setUp: three setup states
        mode = svm.createUint256("mode");
        if (mode == 0) {
            vault = new Vault(10, false);
        } else if (mode == 1) {
            vault = new Vault(500, false);
        } else {
            vault = new Vault(1000, true);
        }
        targetContract(address(vault));
    }

    function check_fee_bounded() public view {
        // holds in every setup state
        assertLe(vault.fee(), 1000);
    }

    function check_fee_small_fail() public view {
        // only holds in the first setup state: counterexample with mode != 0
        assertLe(vault.fee(), 10);
    }

    function check_not_paused_fail() public view {
        // violated in the third setup state only
        assertFalse(vault.paused());
    }

    function check_setFee(uint256 newFee) public {
        vault.setFee(newFee);
        // setFee only succeeds when not paused, and keeps the fee bounded
        assertFalse(vault.paused());
        assertLe(vault.fee(), 1000);
    }

    function invariant_fee_bounded() public view {
        // explored from each setup state, including through setFee() calls
        assertLe(vault.fee(), 1000);
    }

    function invariant_fee_unchanged_fail() public view {
        // setFee() can change the fee in the unpaused setup states
        assertTrue(vault.fee() == 10 || vault.fee() == 500 || vault.fee() == 1000);
    }

    function check_mode_consistent() public view {
        // the test runs against the matching state for each setUp path
        if (mode == 0) assertEq(vault.fee(), 10);
        else if (mode == 1) assertEq(vault.fee(), 500);
        else assertEq(vault.fee(), 1000);
    }
}

/// @dev setUpSymbolic with several successful paths
contract SetupSymbolicMultiTest {
    uint256 public value;

    function setUpSymbolic(uint256 x) public {
        if (x > 10) value = 1;
        else value = 2;
    }

    function check_value() public view {
        assert(value == 1 || value == 2);
    }

    function check_value_fail() public view {
        assert(value == 1);
    }
}
