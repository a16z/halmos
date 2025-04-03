// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract C {
    constructor() payable { }
}

/// @custom:halmos --solver-timeout-assertion 0
contract SendTest is Test, SymTest {
    address sender;
    address payable receiver;
    address others;

    function setUp() public {
        sender = svm.createAddress("sender");
        receiver = payable(svm.createAddress("receiver"));
        others = svm.createAddress("others");

        vm.deal(sender, svm.createUint(96, "sender.balance"));
        vm.deal(receiver, svm.createUint(96, "receiver.balance"));
        vm.deal(others, svm.createUint(96, "others.balance"));
    }

    function check_transfer(uint amount) public {
        vm.assume(others != sender && others != receiver);

        uint oldBalanceSender = sender.balance;
        uint oldBalanceReceiver = receiver.balance;
        uint oldBalanceOthers = others.balance;

        vm.prank(sender);
        receiver.transfer(amount);

        // in case of insufficient funds, transfer() would have already reverted, not reaching here
        assert(oldBalanceSender >= amount);

        uint newBalanceSender = sender.balance;
        uint newBalanceReceiver = receiver.balance;
        uint newBalanceOthers = others.balance;

        unchecked {
            if (receiver != sender) {
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

    function check_send(uint amount, uint mode) public {
        vm.assume(others != sender && others != receiver);

        uint oldBalanceSender = sender.balance;
        uint oldBalanceReceiver = receiver.balance;
        uint oldBalanceOthers = others.balance;

        bool success;
        if (mode == 0) {
            vm.prank(sender);
            success = receiver.send(amount);
        } else {
            vm.prank(sender);
            (success,) = receiver.call{ value: amount }("");
        }

        if (success) {
            assert(oldBalanceSender >= amount);
        }

        uint newBalanceSender = sender.balance;
        uint newBalanceReceiver = receiver.balance;
        uint newBalanceOthers = others.balance;

        unchecked {
            if (success && receiver != sender) {
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

    function check_create(uint amount, bytes32 salt, uint mode) public {
        // note: deployer is set to concrete, to prevent halmos from treating the contract creation target as aliasing with the deployer
        address deployer = address(0xbeef);
        vm.deal(deployer, svm.createUint(96, "deployer.balance"));

        vm.assume(others != deployer && others != receiver);

        uint oldBalanceSender = deployer.balance;
        uint oldBalanceReceiver = receiver.balance;
        uint oldBalanceOthers = others.balance;

        C c;
        if (mode == 0) {
            vm.prank(deployer);
            c = new C{ value: amount }();
        } else {
            vm.prank(deployer);
            c = new C{ value: amount, salt: salt }();
        }
        vm.assume(receiver == address(c));

        uint newBalanceSender = deployer.balance;
        uint newBalanceReceiver = receiver.balance;
        uint newBalanceOthers = others.balance;

        if (oldBalanceSender >= amount) {
            unchecked {
                assert(receiver != deployer); // new address cannot be equal to the deployer
                assert(newBalanceSender == oldBalanceSender - amount);
                assert(newBalanceSender <= oldBalanceSender);
                assert(newBalanceReceiver == oldBalanceReceiver + amount);
                assert(newBalanceReceiver >= oldBalanceReceiver);
                assert(oldBalanceSender + oldBalanceReceiver == newBalanceSender + newBalanceReceiver);
                assert(oldBalanceOthers == newBalanceOthers);
            }
        } else {
            assert(newBalanceSender == oldBalanceSender);
            assert(newBalanceReceiver == oldBalanceReceiver);
        }
    }

    receive() external payable {}
}
