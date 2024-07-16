// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract BlockNumberTest is Test {
    uint256 blockNumber;

    function setUp() public {
        blockNumber = block.number;
    }

    function check_GetBlockNumber() public {
        uint256 vmBlockNumber = vm.getBlockNumber();

        assert(vmBlockNumber == blockNumber);
    }

    function check_GetBlockNumber_AfterAdvance() public {
        // Advance the block number by 1000 blocks
        vm.roll(blockNumber + 1000);
        uint256 newBlockNumber = vm.getBlockNumber();

        assert(newBlockNumber == blockNumber + 1000);
    }
}
