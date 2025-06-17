// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {Test} from "forge-std/Test.sol";

import {IERC721} from "forge-std/interfaces/IERC721.sol";

abstract contract ERC721InvariantTest is Test {
    address internal token;
    address internal deployer;
    address[] internal accounts;

    function setUp() public virtual {
        // setup target senders
        for (uint i = 0; i < accounts.length; i++) {
            targetSender(accounts[i]);
        }

        // setup target contracts
        targetContract(token);
    }

    function invariant_ownerHasAtLeastOneToken() public {
        uint256 tokenId = vm.randomUint();
        assertGe(IERC721(token).balanceOf(IERC721(token).ownerOf(tokenId)), 1);
    }
}
