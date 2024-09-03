// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {ERC721Test} from "./ERC721Test.sol";

import {OpenZeppelinERC721} from "../src/OpenZeppelinERC721.sol";

/// @custom:halmos --solver-timeout-assertion 0
contract OpenZeppelinERC721Test is ERC721Test {

    /// @custom:halmos --solver-timeout-branching 1000
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
        vm.startPrank(deployer);
        token_.transferFrom(deployer, accounts[0], tokenIds[0]);
        token_.transferFrom(deployer, accounts[0], tokenIds[1]);
        token_.transferFrom(deployer, accounts[1], tokenIds[2]);
        token_.transferFrom(deployer, accounts[2], tokenIds[3]);
        vm.stopPrank();

        vm.prank(accounts[0]);
        token_.approve(accounts[2], tokenIds[0]);

        vm.prank(accounts[1]);
        token_.setApprovalForAll(accounts[2], true);
    }

    // TODO: remove bytes4 parameter after updating expected output
    function check_NoBackdoor(bytes4) public {
        bytes memory _calldata = CreateCalldata(address(svm)).createCalldata("OpenZeppelinERC721");
        _check_NoBackdoor(_calldata);
    }
}

// TODO: remove this after updating halmos-cheatcode submodule
interface CreateCalldata {
    // Create calldata
    function createCalldata(string memory filename, string memory contractName) external pure returns (bytes memory data);

    function createCalldata(string memory contractName) external pure returns (bytes memory data);
}
