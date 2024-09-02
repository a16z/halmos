// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Test} from "forge-std/Test.sol";

import {IERC721} from "forge-std/interfaces/IERC721.sol";

abstract contract ERC721Test is SymTest, Test {
    address internal token;
    address internal deployer;
    address[] internal accounts;
    uint256[] internal tokenIds;

    function setUp() public virtual;

    function _check_NoBackdoor(bytes memory _calldata) public virtual {
        // consider caller and other that are distinct
        address caller = svm.createAddress('caller');
        address other = svm.createAddress('other');
        vm.assume(caller != other);

        // assume the caller hasn't been granted any approvals
        for (uint i = 0; i < accounts.length; i++) {
            vm.assume(!IERC721(token).isApprovedForAll(accounts[i], caller));
        }
        for (uint i = 0; i < tokenIds.length; i++) {
            vm.assume(IERC721(token).getApproved(tokenIds[i]) != caller);
        }

        // record their current balances
        uint256 oldBalanceCaller = IERC721(token).balanceOf(caller);
        uint256 oldBalanceOther = IERC721(token).balanceOf(other);

        // consider an arbitrary function call to the token from the caller
        vm.prank(caller);
        (bool success,) = address(token).call(_calldata);
        vm.assume(success);

        // ensure that the caller cannot spend other's tokens
        assert(IERC721(token).balanceOf(caller) <= oldBalanceCaller);
        assert(IERC721(token).balanceOf(other) >= oldBalanceOther);
    }

    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view returns (bool) {
        address owner = IERC721(token).ownerOf(tokenId);
        return (spender == owner || IERC721(token).isApprovedForAll(owner, spender) || IERC721(token).getApproved(tokenId) == spender);
    }

    function check_transferFrom(address caller, address from, address to, address other, uint256 tokenId, uint256 otherTokenId) public virtual {
        // not realistic in practice
        // and in particular msg.sender == address(0) disables auth for OpenZeppelin ERC721
        vm.assume(caller != address(0));

        // consider other address
        vm.assume(other != from);
        vm.assume(other != to);

        // consider other token ids
        vm.assume(otherTokenId != tokenId);

        // record their current balance
        uint256 oldBalanceFrom   = IERC721(token).balanceOf(from);
        uint256 oldBalanceTo     = IERC721(token).balanceOf(to);
        uint256 oldBalanceOther  = IERC721(token).balanceOf(other);

        // record their current owner
        address oldOwner = IERC721(token).ownerOf(tokenId);
        address oldOtherTokenOwner = IERC721(token).ownerOf(otherTokenId);

        // record the current approvals
        bool approved = _isApprovedOrOwner(caller, tokenId);

        vm.prank(caller);
        if (svm.createBool('?')) {
            IERC721(token).transferFrom(from, to, tokenId);
        } else {
            IERC721(token).safeTransferFrom(from, to, tokenId, svm.createBytes(96, 'data'));
        }

        // ensure requirements of transfer
        assertEq(from, oldOwner);
        assertTrue(approved);

        // ensure the owner is updated correctly
        assertEq(IERC721(token).ownerOf(tokenId), to);
        assertEq(IERC721(token).getApproved(tokenId), address(0)); // ensure the approval is reset

        // ensure the other token's owner is unchanged
        assertEq(IERC721(token).ownerOf(otherTokenId), oldOtherTokenOwner);

        // balance update
        if (from != to) {
            assertLt(IERC721(token).balanceOf(from), oldBalanceFrom);
            assertEq(IERC721(token).balanceOf(from), oldBalanceFrom - 1);
            assertGt(IERC721(token).balanceOf(to), oldBalanceTo);
            assertEq(IERC721(token).balanceOf(to), oldBalanceTo + 1);
        } else {
            assertEq(IERC721(token).balanceOf(from), oldBalanceFrom);
            assertEq(IERC721(token).balanceOf(to), oldBalanceTo);
        }
        assertEq(IERC721(token).balanceOf(other), oldBalanceOther);
    }
}
