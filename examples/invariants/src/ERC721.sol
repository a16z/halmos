// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {ERC721 as OpenZeppelinERC721} from "openzeppelin/token/ERC721/ERC721.sol";
import {Ownable} from "openzeppelin/access/Ownable.sol";

contract ERC721 is OpenZeppelinERC721, Ownable {
    constructor(string memory name, string memory symbol) OpenZeppelinERC721(name, symbol) Ownable(msg.sender) { }

    function mint(address to, uint256 tokenId) public virtual onlyOwner {
        _mint(to, tokenId);
    }
}
