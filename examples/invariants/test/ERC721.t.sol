// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {ERC721} from "../src/ERC721.sol";
import {Test} from "forge-std/Test.sol";

/// @custom:halmos --solver bitwuzla-abs --solver-timeout-assertion 0
contract ERC721Test is Test {
    // ERC721 token address
    ERC721 internal token;

    function setUp() public virtual {
        // deploy ERC721 token
        token = new ERC721("ERC721", "ERC721");

        // mint initial tokens
        token.mint(address(0x1001), 1);
        token.mint(address(0x1001), 2);
        token.mint(address(0x1002), 3);
        token.mint(address(0x1003), 4);

        // register the token contract as the target for invariant testing
        targetContract(address(token));
    }

    // invariant: the owner of any token ID must have at least one token
    function invariant_ownerHasAtLeastOneToken() public {
        uint256 tokenId = vm.randomUint();
        try token.ownerOf(tokenId) returns (address owner) {
            assertGe(token.balanceOf(owner), 1);
        } catch {
            // nothing to do if the token does not exist
        }
    }
}
