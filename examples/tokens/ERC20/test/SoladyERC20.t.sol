// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {ERC20Test} from "./ERC20Test.sol";

import {SoladyERC20} from "../src/SoladyERC20.sol";

/// @custom:halmos --custom-storage-layout --solver-timeout-assertion 0
contract SoladyERC20Test is ERC20Test {
    function setUp() public override {
        address deployer = address(0x1000);

        SoladyERC20 token_ = new SoladyERC20("SoladyERC20", "SoladyERC20", 18, 1_000_000_000e18, deployer);
        token = address(token_);

        holders = new address[](3);
        holders[0] = address(0x1001);
        holders[1] = address(0x1002);
        holders[2] = address(0x1003);

        for (uint i = 0; i < holders.length; i++) {
            address account = holders[i];
            uint256 balance = svm.createUint256('balance');
            vm.prank(deployer);
            token_.transfer(account, balance);
            for (uint j = 0; j < i; j++) {
                address other = holders[j];
                uint256 amount = svm.createUint256('amount');
                vm.prank(account);
                token_.approve(other, amount);
            }
        }
    }

    function check_NoBackdoor(bytes4 selector, address caller, address other) public {
        bytes memory args = svm.createBytes(1024, 'data');
        _checkNoBackdoor(selector, args, caller, other);
    }
}
