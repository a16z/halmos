// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract BlockCheatCodeTest is Test {
    function checkFee(uint x) public {
        vm.fee(x);
        assert(block.basefee == x);
    }

    function checkChainId(uint64 x) public {
        vm.chainId(x);
        assert(block.chainid == x);
    }

    function checkCoinbase(address x) public {
        vm.coinbase(x);
        assert(block.coinbase == x);
    }

    function checkDifficulty(uint x) public {
        vm.difficulty(x);
        assert(block.difficulty == x);
    }

    function checkRoll(uint x) public {
        vm.roll(x);
        assert(block.number == x);
    }

    function checkWarp(uint x) public {
        vm.warp(x);
        assert(block.timestamp == x);
    }
}
