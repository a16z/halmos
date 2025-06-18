// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {ERC721} from "../src/ERC721.sol";
import {Test} from "forge-std/Test.sol";

/// @custom:halmos --solver bitwuzla-abs --loop 3 --solver-timeout-assertion 0
contract ERC721Test is Test {
    // token address
    ERC721 internal token;

    // token holders
    address[] internal accounts;

    function setUp() public virtual {
        // deploy token
        address deployer = address(0x1000);
        vm.prank(deployer);
        token = new ERC721("ERC721", "ERC721");

        // declare token holders
        accounts = new address[](3);
        accounts[0] = address(0x1001);
        accounts[1] = address(0x1002);
        accounts[2] = address(0x1003);

        // setup initial balances
        vm.startPrank(deployer);
        token.mint(accounts[0], 1);
        token.mint(accounts[0], 2);
        token.mint(accounts[1], 3);
        token.mint(accounts[2], 4);
        vm.stopPrank();

        // setup target senders
        targetSender(deployer);
        for (uint i = 0; i < accounts.length; i++) {
            targetSender(accounts[i]);
        }

        // setup target contracts
        targetContract(address(token));
    }

    function invariant_ownerHasAtLeastOneToken() public {
        uint256 tokenId = vm.randomUint();
        assertGe(token.balanceOf(token.ownerOf(tokenId)), 1);
    }
}
