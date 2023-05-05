// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract SendTest {

    function testSend(address payable receiver, uint amount, address others) public {
        require(others != address(this) && others != receiver);

        require(address(this) != receiver);

        uint oldBalanceSender = address(this).balance;
        uint oldBalanceReceiver = receiver.balance;
        uint oldBalanceOthers = others.balance;

        receiver.transfer(amount);

        uint newBalanceSender = address(this).balance;
        uint newBalanceReceiver = receiver.balance;
        uint newBalanceOthers = others.balance;

        unchecked {
            assert(newBalanceSender == oldBalanceSender - amount);
            assert(newBalanceReceiver == oldBalanceReceiver + amount);
            assert(oldBalanceSender + oldBalanceReceiver == newBalanceSender + newBalanceReceiver);
            assert(oldBalanceOthers == newBalanceOthers);
        }
    }

    function testSendSelf(address payable receiver, uint amount, address others) public {
        require(others != address(this) && others != receiver);

        require(address(this) == receiver);

        uint oldBalanceSender = address(this).balance;
        uint oldBalanceReceiver = receiver.balance;
        uint oldBalanceOthers = others.balance;

        receiver.transfer(amount);

        uint newBalanceSender = address(this).balance;
        uint newBalanceReceiver = receiver.balance;
        uint newBalanceOthers = others.balance;

        unchecked {
            assert(newBalanceSender == oldBalanceSender);
            assert(newBalanceReceiver == oldBalanceReceiver);
            assert(oldBalanceSender + oldBalanceReceiver == newBalanceSender + newBalanceReceiver);
            assert(oldBalanceOthers == newBalanceOthers);
        }
    }
}
