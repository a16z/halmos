// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {ERC20} from "solmate/tokens/ERC20.sol";

contract SolmateERC20 is ERC20 {
    constructor(string memory _name, string memory _symbol, uint8 _decimals, uint256 initialSupply, address deployer) ERC20(_name, _symbol, _decimals) {
        _mint(deployer, initialSupply);
    }
}
