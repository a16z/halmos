// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract BlockCheatCodeTest is Test {
    function check_fee(uint x) public {
        assertEq(block.basefee, 0); // foundry default value
        vm.fee(x);
        assert(block.basefee == x);
    }

    function check_chainId(uint64 x) public {
        assertEq(block.chainid, 31337); // foundry default value
        vm.chainId(x);
        assert(block.chainid == x);
    }

    function check_coinbase(address x) public {
        assertEq(block.coinbase, address(0)); // foundry default value
        vm.coinbase(x);
        assert(block.coinbase == x);
    }

    function check_difficulty(uint x) public {
        assertEq(block.difficulty, 0); // foundry default value
        vm.difficulty(x);
        assert(block.difficulty == x);
    }

    function check_gaslimit() public {
        assertEq(block.gaslimit, 2**63 - 1); // foundry default value
    }

    function check_roll(uint x) public {
        assertEq(block.number, 1); // foundry default value
        vm.roll(x);
        assert(block.number == x);
    }

    function check_warp(uint x) public {
        assertEq(block.timestamp, 1); // foundry default value
        vm.warp(x);
        assert(block.timestamp == x);
    }
}
