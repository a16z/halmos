// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract InvariantMsgValueTarget {
    uint256 public totalMsgValue;
    uint256 public nonpayableCalls;

    function deposit() external payable {
        totalMsgValue += msg.value;
    }

    function touch() external {
        nonpayableCalls++;
    }
}

contract InvariantMsgValueTest is Test {
    address constant SENDER = address(0xbeef);
    uint256 constant SENDER_INITIAL_BALANCE = 2 ether;
    uint256 constant TARGET_INITIAL_BALANCE = 1 ether;

    InvariantMsgValueTarget target;

    function setUp() public {
        target = new InvariantMsgValueTarget();

        vm.deal(SENDER, SENDER_INITIAL_BALANCE);
        vm.deal(address(target), TARGET_INITIAL_BALANCE);

        targetContract(address(target));
        targetSender(SENDER);
    }

    /// @custom:halmos --invariant-depth 1
    function invariant_msg_value_transfer() public view {
        // At depth one, this is the msg.value observed by the target call.
        uint256 totalMsgValue = target.totalMsgValue();

        assertLe(totalMsgValue, SENDER_INITIAL_BALANCE);
        assertEq(SENDER.balance + totalMsgValue, SENDER_INITIAL_BALANCE);
        assertEq(
            address(target).balance,
            TARGET_INITIAL_BALANCE + totalMsgValue
        );
    }

    /// @custom:halmos --invariant-depth 1
    function invariant_msg_value_can_be_positive() public view {
        // Expected counterexample: deposit receives a positive, funded msg.value.
        assertEq(target.totalMsgValue(), 0);
    }
}
