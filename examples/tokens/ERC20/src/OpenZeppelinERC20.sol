// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {ERC20} from "openzeppelin/token/ERC20/ERC20.sol";

contract OpenZeppelinERC20 is ERC20 {
    constructor(string memory name, string memory symbol, uint256 initialSupply, address deployer) ERC20(name, symbol) {
        _mint(deployer, initialSupply);
    }
}
