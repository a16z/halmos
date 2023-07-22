// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {ERC721Test} from "./ERC721Test.sol";

import {OpenZeppelinERC721} from "../src/OpenZeppelinERC721.sol";

/// @custom:halmos --solver-timeout-assertion 0
contract OpenZeppelinERC721Test is ERC721Test {
    function setUp() public override {
        deployer = address(0x1000);

        OpenZeppelinERC721 token_ = new OpenZeppelinERC721("OpenZeppelinERC721", "OpenZeppelinERC721", 5, deployer);
        token = address(token_);

        accounts = new address[](3);
        accounts[0] = address(0x1001);
        accounts[1] = address(0x1002);
        accounts[2] = address(0x1003);

        tokenIds = new uint256[](5);
        tokenIds[0] = 1;
        tokenIds[1] = 2;
        tokenIds[2] = 3;
        tokenIds[3] = 4;
        tokenIds[4] = 5;

        // account0: {token0, token1}, account1: {token2}, account2: {token3}
        vm.prank(deployer);
        token_.transferFrom(deployer, accounts[0], tokenIds[0]);
        vm.prank(deployer);
        token_.transferFrom(deployer, accounts[0], tokenIds[1]);
        vm.prank(deployer);
        token_.transferFrom(deployer, accounts[1], tokenIds[2]);
        vm.prank(deployer);
        token_.transferFrom(deployer, accounts[2], tokenIds[3]);

        vm.prank(accounts[0]);
        token_.approve(accounts[2], tokenIds[0]);

        vm.prank(accounts[1]);
        token_.setApprovalForAll(accounts[2], true);
    }
}
