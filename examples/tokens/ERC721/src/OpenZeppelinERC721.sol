// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {ERC721} from "openzeppelin/token/ERC721/ERC721.sol";

contract OpenZeppelinERC721 is ERC721 {
    constructor(string memory name, string memory symbol, uint256 initialSupply, address deployer) ERC721(name, symbol) {
        for (uint256 i = 1; i <= initialSupply; i++) {
            _mint(deployer, i);
        }
    }
}
