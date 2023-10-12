// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract BlockCheatCodeTest is Test {
    function check_fee(uint x) public {
        vm.fee(x);
        assert(block.basefee == x);
    }

    function check_chainId(uint64 x) public {
        vm.chainId(x);
        assert(block.chainid == x);
    }

    function check_coinbase(address x) public {
        vm.coinbase(x);
        assert(block.coinbase == x);
    }

    function check_difficulty(uint x) public {
        vm.difficulty(x);
        assert(block.difficulty == x);
    }

    function check_roll(uint x) public {
        vm.roll(x);
        assert(block.number == x);
    }

    function check_warp(uint x) public {
        vm.warp(x);
        assert(block.timestamp == x);
    }
}
