// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Test} from "forge-std/Test.sol";

import {IERC20} from "forge-std/interfaces/IERC20.sol";

abstract contract ERC20Test is SymTest, Test {
    // erc20 token address
    address internal token;

    // token holders
    address[] internal holders;

    function setUp() public virtual;

    function _checkNoBackdoor(bytes4 selector, bytes memory args, address caller, address other) public virtual {
        // consider two arbitrary distinct accounts
        vm.assume(other != caller);

        // record their current balances
        uint256 oldBalanceOther = IERC20(token).balanceOf(other);

        uint256 oldAllowance = IERC20(token).allowance(other, caller);

        // consider an arbitrary function call to the token from the caller
        vm.prank(caller);
        (bool success,) = address(token).call(abi.encodePacked(selector, args));
        vm.assume(success);

        uint256 newBalanceOther = IERC20(token).balanceOf(other);

        // ensure that the caller cannot spend other' tokens without approvals
        if (newBalanceOther < oldBalanceOther) {
            assert(oldAllowance >= oldBalanceOther - newBalanceOther);
        }
    }

    function check_transfer(address sender, address receiver, address other, uint256 amount) public virtual {
        // consider other that are neither sender or receiver
        require(other != sender);
        require(other != receiver);

        // record their current balance
        uint256 oldBalanceSender   = IERC20(token).balanceOf(sender);
        uint256 oldBalanceReceiver = IERC20(token).balanceOf(receiver);
        uint256 oldBalanceOther   = IERC20(token).balanceOf(other);

        vm.prank(sender);
        IERC20(token).transfer(receiver, amount);

        if (sender != receiver) {
            assert(IERC20(token).balanceOf(sender) <= oldBalanceSender); // ensure no subtraction overflow
            assert(IERC20(token).balanceOf(sender) == oldBalanceSender - amount);
            assert(IERC20(token).balanceOf(receiver) >= oldBalanceReceiver); // ensure no addition overflow
            assert(IERC20(token).balanceOf(receiver) == oldBalanceReceiver + amount);
        } else {
            // sender and receiver may be the same
            assert(IERC20(token).balanceOf(sender) == oldBalanceSender);
            assert(IERC20(token).balanceOf(receiver) == oldBalanceReceiver);
        }
        // make sure other balance is not affected
        assert(IERC20(token).balanceOf(other) == oldBalanceOther);
    }

    function check_transferFrom(address caller, address from, address to, address other, uint256 amount) public virtual {
        require(other != from);
        require(other != to);

        uint256 oldBalanceFrom   = IERC20(token).balanceOf(from);
        uint256 oldBalanceTo     = IERC20(token).balanceOf(to);
        uint256 oldBalanceOther = IERC20(token).balanceOf(other);

        uint256 oldAllowance = IERC20(token).allowance(from, caller);

        vm.prank(caller);
        IERC20(token).transferFrom(from, to, amount);

        if (from != to) {
            assert(IERC20(token).balanceOf(from) <= oldBalanceFrom);
            assert(IERC20(token).balanceOf(from) == oldBalanceFrom - amount);
            assert(IERC20(token).balanceOf(to) >= oldBalanceTo);
            assert(IERC20(token).balanceOf(to) == oldBalanceTo + amount);

            assert(oldAllowance >= amount); // ensure allowance was enough
            assert(oldAllowance == type(uint256).max || IERC20(token).allowance(from, caller) == oldAllowance - amount); // allowance decreases if not max
        } else {
            assert(IERC20(token).balanceOf(from) == oldBalanceFrom);
            assert(IERC20(token).balanceOf(to) == oldBalanceTo);
        }
        assert(IERC20(token).balanceOf(other) == oldBalanceOther);
    }
}
