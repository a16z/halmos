// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {Test} from "forge-std/Test.sol";

import {IERC20} from "forge-std/interfaces/IERC20.sol";

abstract contract ERC20InvariantTest is Test {
    // erc20 token address
    address internal token;

    // token holders
    address[] internal holders;

    function setUp() public virtual {
        // setup target senders
        for (uint i = 0; i < holders.length; i++) {
            targetSender(holders[i]);
        }

        // setup target contracts
        targetContract(token);

        bytes4[] memory selectors;

        // specify handlers
        targetContract(address(this));
        selectors = new bytes4[](2);
        selectors[0] = this.transfer.selector;
        selectors[1] = this.transferFrom.selector;
        targetSelector(FuzzSelector({
            addr: address(this),
            selectors: selectors
        }));

        // exclude original functions that are replaced by handlers
        selectors = new bytes4[](2);
        selectors[0] = IERC20(token).transfer.selector;
        selectors[1] = IERC20(token).transferFrom.selector;
        excludeSelector(FuzzSelector({
            addr: token,
            selectors: selectors
        }));
    }

    // handlers

    function transfer(address to, uint256 amount) public returns (bool) {
        vm.assume(_contains(holders, to));
        vm.prank(msg.sender);
        return IERC20(token).transfer(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        vm.assume(_contains(holders, to));
        vm.prank(msg.sender);
        return IERC20(token).transferFrom(from, to, amount);
    }

    function _contains(address[] storage array, address value) internal view returns (bool) {
        for (uint256 i = 0; i < array.length; i++) {
            if (array[i] == value) {
                return true;
            }
        }
        return false;
    }

    // invariants

    // from https://github.com/aviggiano/halmos-stateful-erc20
    function invariant_sumOfBalancesEqualsTotalSupply() public view {
        uint256 sumOfBalances = 0;
        for (uint256 i = 0; i < holders.length; i++) {
            sumOfBalances += IERC20(token).balanceOf(holders[i]);
        }
        assertEq(sumOfBalances, IERC20(token).totalSupply());
    }
}
