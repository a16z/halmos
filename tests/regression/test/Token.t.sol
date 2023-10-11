// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Test} from "forge-std/Test.sol";

/// @custom:halmos --solver-timeout-assertion 0
contract TokenTest is SymTest, Test {
    Token token;

    function setUp() public {
        token = new Token();

        // set the balances of three arbitrary accounts to arbitrary symbolic values
        for (uint i = 0; i < 3; i++) {
            address receiver = svm.createAddress('receiver');
            uint256 amount = svm.createUint256('amount');
            token.transfer(receiver, amount);
        }
    }

    function check_BalanceInvariant() public {
        // consider two arbitrary distinct accounts
        address caller = svm.createAddress('caller');
        address others = svm.createAddress('others');
        vm.assume(others != caller);

        // record their current balances
        uint256 oldBalanceCaller = token.balanceOf(caller);
        uint256 oldBalanceOthers = token.balanceOf(others);

        // consider an arbitrary function call to the token from the caller
        vm.prank(caller);
        bytes memory data = svm.createBytes(100, 'data');
        (bool success,) = address(token).call(data);
        vm.assume(success);

        // ensure that the caller cannot spend others' tokens
        assert(token.balanceOf(caller) <= oldBalanceCaller);
        assert(token.balanceOf(others) >= oldBalanceOthers);
    }
}

contract Token {
    mapping(address => uint) public balanceOf;

    constructor() {
        balanceOf[msg.sender] = 1e27;
    }

    function transfer(address to, uint amount) public {
        _transfer(msg.sender, to, amount);
    }

    function _transfer(address from, address to, uint amount) public {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}
