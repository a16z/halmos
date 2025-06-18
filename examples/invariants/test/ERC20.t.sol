// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

// inspired by https://github.com/aviggiano/halmos-stateful-erc20

import {ERC20} from "../src/ERC20.sol";
import {Test} from "forge-std/Test.sol";

/// @custom:halmos --solver bitwuzla-abs --loop 3
contract ERC20Test is Test {
    // token address
    ERC20 internal token;

    // token holders
    address[] internal holders;

    function setUp() public virtual {
        // deploy token
        address deployer = address(0x1000);
        vm.prank(deployer);
        token = new ERC20("ERC20", "ERC20");

        // declare token holders
        holders = new address[](3);
        holders[0] = address(0x1001);
        holders[1] = address(0x1002);
        holders[2] = address(0x1003);

        // setup initial balances
        for (uint i = 1; i < holders.length; i++) {
            vm.prank(deployer);
            token.mint(holders[i], 1_000_000e18);
        }

        // setup target senders
        targetSender(deployer);
        for (uint i = 0; i < holders.length; i++) {
            targetSender(holders[i]);
        }

        // setup target contracts
        targetContract(address(token));

        bytes4[] memory selectors;

        // specify handlers
        targetContract(address(this));
        selectors = new bytes4[](3);
        selectors[0] = this.transfer.selector;
        selectors[1] = this.transferFrom.selector;
        selectors[2] = this.mint.selector;
        targetSelector(FuzzSelector({
            addr: address(this),
            selectors: selectors
        }));

        // exclude original functions that are replaced by handlers
        selectors = new bytes4[](3);
        selectors[0] = token.transfer.selector;
        selectors[1] = token.transferFrom.selector;
        selectors[2] = token.mint.selector;
        excludeSelector(FuzzSelector({
            addr: address(token),
            selectors: selectors
        }));
    }

    // handlers

    function transfer(address to, uint256 amount) public returns (bool) {
        vm.assume(_contains(holders, to));
        vm.prank(msg.sender);
        return token.transfer(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public returns (bool) {
        vm.assume(_contains(holders, to));
        vm.prank(msg.sender);
        return token.transferFrom(from, to, amount);
    }

    function mint(address to, uint256 amount) public {
        vm.assume(_contains(holders, to));
        vm.prank(msg.sender);
        return token.mint(to, amount);
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

    function invariant_sumOfBalancesEqualsTotalSupply() public view {
        uint256 sumOfBalances = 0;
        for (uint256 i = 0; i < holders.length; i++) {
            sumOfBalances += token.balanceOf(holders[i]);
        }
        assertEq(sumOfBalances, token.totalSupply());
    }
}
