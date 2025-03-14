// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract WithProbes {
    uint public num;
    bool public unlocked;

    // should always trigger (but be reported only once)
    function probe0() public {
        assert(false);
    }

    // requires some exploration before triggering
    function probe1() public {
        if (num == 1) {
            assert(false);
        }

        if (num > 1) {
            unlocked = true;
        }
    }

    // requires state change produced by probe1() to trigger
    function probe2() public {
        if (unlocked) {
            assert(false);
        }
    }

    function inc() public {
        num += 1;
    }
}

contract InvariantProbesTest is Test {
    WithProbes c;

    function setUp() public {
        c = new WithProbes();
    }

    // XFAIL: we should report failures when asserts are hit in the target contract
    /// @custom:halmos --invariant-depth 4
    function invariant_probes_found() public {
        assertGe(c.num(), 0);
    }
}
