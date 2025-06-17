// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {ERC20} from "solmate/tokens/ERC20.sol";

contract BuggyERC20 is ERC20 {
    constructor(string memory _name, string memory _symbol, uint8 _decimals, uint256 initialSupply, address deployer) ERC20(_name, _symbol, _decimals) {
        _mint(deployer, initialSupply);
    }

    // buggy transfer
    function transfer(address to, uint256 value) public virtual override returns (bool) {
        address from = msg.sender;
        uint256 fromBalance = balanceOf[from];
        uint256 toBalance = balanceOf[to];
        balanceOf[from] = fromBalance - value;
        balanceOf[to] = toBalance + value;
        return true;
    }
}
