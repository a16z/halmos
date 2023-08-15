// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

/// @custom:halmos --solver-timeout-assertion 0
contract SendTest {

    function check_transfer(address payable receiver, uint amount, address others) public {
        require(others != address(this) && others != receiver);

        uint oldBalanceSender = address(this).balance;
        uint oldBalanceReceiver = receiver.balance;
        uint oldBalanceOthers = others.balance;

        receiver.transfer(amount);

        assert(oldBalanceSender >= amount);

        uint newBalanceSender = address(this).balance;
        uint newBalanceReceiver = receiver.balance;
        uint newBalanceOthers = others.balance;

        unchecked {
            if (receiver != address(this)) {
                assert(newBalanceSender == oldBalanceSender - amount);
                assert(newBalanceSender <= oldBalanceSender);
                assert(newBalanceReceiver == oldBalanceReceiver + amount);
                assert(newBalanceReceiver >= oldBalanceReceiver);
            } else {
                assert(newBalanceSender == oldBalanceSender);
                assert(newBalanceReceiver == oldBalanceReceiver);
            }
            assert(oldBalanceSender + oldBalanceReceiver == newBalanceSender + newBalanceReceiver);
            assert(oldBalanceOthers == newBalanceOthers);
        }
    }

    function check_send(address payable receiver, uint amount, address others, uint mode) public {
        require(others != address(this) && others != receiver);

        uint oldBalanceSender = address(this).balance;
        uint oldBalanceReceiver = receiver.balance;
        uint oldBalanceOthers = others.balance;

        bool success;
        if (mode == 0) {
            success = receiver.send(amount);
        } else {
            (success,) = receiver.call{ value: amount }("");
        }

        if (success) {
            assert(oldBalanceSender >= amount);
        }

        uint newBalanceSender = address(this).balance;
        uint newBalanceReceiver = receiver.balance;
        uint newBalanceOthers = others.balance;

        unchecked {
            if (success && receiver != address(this)) {
                assert(newBalanceSender == oldBalanceSender - amount);
                assert(newBalanceSender <= oldBalanceSender);
                assert(newBalanceReceiver == oldBalanceReceiver + amount);
                assert(newBalanceReceiver >= oldBalanceReceiver);
            } else {
                assert(newBalanceSender == oldBalanceSender);
                assert(newBalanceReceiver == oldBalanceReceiver);
            }
            assert(oldBalanceSender + oldBalanceReceiver == newBalanceSender + newBalanceReceiver);
            assert(oldBalanceOthers == newBalanceOthers);
        }
    }

    receive() external payable {}
}
