// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {ERC20InvariantTest} from "./ERC20InvariantTest.sol";

import {BuggyERC20} from "../src/BuggyERC20.sol";

/// @custom:halmos --solver bitwuzla-abs --loop 4 --early-exit
contract BuggyERC20InvariantTest is ERC20InvariantTest {
    function setUp() public override {
        address deployer = address(0x1000);

        // deploy token
        BuggyERC20 token_ = new BuggyERC20("BuggyERC20", "BuggyERC20", 18, 1_000_000_000e18, deployer);
        token = address(token_);

        holders = new address[](4);
        holders[0] = deployer;
        holders[1] = address(0x1001);
        holders[2] = address(0x1002);
        holders[3] = address(0x1003);

        // setup initial balances
        for (uint i = 1; i < holders.length; i++) {
            vm.prank(deployer);
            token_.transfer(holders[i], 1_000_000e18);
        }

        super.setUp();
    }
}
