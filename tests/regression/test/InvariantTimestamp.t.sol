// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "halmos-cheatcodes/SymTest.sol";

contract TimeKeeper {
    mapping(address => uint256) public registered;
    uint256 public numRegistrations;

    function register() public {
        registered[msg.sender] = block.timestamp;
        numRegistrations++;
    }

    function elapsed(address sender) public view returns (uint256) {
        uint256 registrationTime = registered[sender];
        if (registrationTime == 0) {
            return 0;
        }

        return block.timestamp - registrationTime;
    }
}

contract InvariantTimestampTest is Test, SymTest {
    TimeKeeper timeKeeper;
    uint256 startTime;

    function setUp() public {
        timeKeeper = new TimeKeeper();

        // by default, the starting timestamp is 1
        // we can start with an arbitrary timestamp by warping in setUp()
        startTime = svm.createUint(64, "startTime");
        vm.warp(startTime);
    }

    // we expect a PASS (this checks that the warp in setUp() is working)
    function check_timestamp_setup() external view {
        assertEq(startTime, block.timestamp);
    }

    // XFAIL -- this checks that the warp in setUp() is working
    function invariant_timestamp_setup() external view {
        assertEq(1, block.timestamp);
    }

    // XFAIL -- this checks that time can change during invariant testing
    function invariant_timestamp_can_change() external view {
        assertEq(startTime, block.timestamp);
    }

    // XFAIL -- this checks that time can remain the same during invariant testing
    function invariant_timestamp_does_not_have_to_change() external view {
        // we want to avoid the check at depth=0 (running the invariant on the setUp state itself)
        if (timeKeeper.numRegistrations() > 0) {
            assertNotEq(startTime, block.timestamp);
        }
    }

    // we expect a PASS here
    function invariant_timestamp_can_only_move_forward() external view {
        assertGe(block.timestamp, startTime);
    }

    // we expect a PASS here
    function invariant_timestamp_is_bounded() external view {
        assertLe(block.timestamp, 2**64);
    }

    // XFAIL -- this checks that time can change during invariant testing (via external contract)
    // (a PASS would mean that time can not move forward)
    function invariant_timestamp_timekeeper(address sender) external view {
        assertEq(0, timeKeeper.elapsed(sender));
    }
}
