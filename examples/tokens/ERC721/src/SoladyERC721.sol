// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {ERC721} from "solady/tokens/ERC721.sol";

contract SoladyERC721 is ERC721 {
    string internal _name;
    string internal _symbol;

    constructor(
        string memory name_,
        string memory symbol_,
        uint256 initialSupply,
        address deployer
    ) {
        _name = name_;
        _symbol = symbol_;

        for (uint256 i = 1; i <= initialSupply; i++) {
            _mint(deployer, i);
        }
    }

    function name() public view virtual override returns (string memory) {
        return _name;
    }

    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }

    function tokenURI(uint256) public view virtual override returns (string memory) {}
}
