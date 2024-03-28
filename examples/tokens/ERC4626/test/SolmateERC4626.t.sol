// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {ERC4626Test} from "./ERC4626Test.sol";

import {SolmateERC20} from "../src/SolmateERC20.sol";
import {SolmateERC4626} from "../src/SolmateERC4626.sol";

contract SolmateERC4626Test is ERC4626Test {
    function setUp() public override {
        address assetDeployer = address(0x1000);
        SolmateERC20 asset = new SolmateERC20("SolmateERC20", "SolmateERC20", 18, 1_000_000_000e18, assetDeployer);

        holders = new address[](2);
        holders[0] = address(0x1001);
        holders[1] = address(0x1002);

        for (uint i = 0; i < holders.length; i++) {
            address account = holders[i];
            uint256 balance = svm.createUint256('balance');
            vm.prank(assetDeployer); asset.transfer(account, balance);
        }

        SolmateERC4626 vault_ = new SolmateERC4626(asset, "SolmateERC4626", "SolmateERC4626");
        vault = address(vault_);

        for (uint i = 0; i < holders.length; i++) {
            address user = holders[i];
            uint256 shares = svm.createUint256('shares');
            vm.prank(user); asset.approve(vault, type(uint).max);
            vm.prank(user); vault_.deposit(shares, user);
        }

        uint256 gain = svm.createUint256('gain');
        vm.prank(assetDeployer); asset.transfer(vault, gain);
    }
}
