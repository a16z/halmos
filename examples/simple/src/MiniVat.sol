// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.17;

/// @notice from https://github.com/baolean/symexec-bench/blob/main/Vat/MiniVat.sol

contract MiniVat {
    uint256 public debt;
    mapping(address => uint256) public art;
    mapping(address => uint256) public dai;
    uint256 public Art;
    uint256 public rate;

    function init() public {
        require(rate == 0, "rate not zero");
        rate = 10 ** 27;
    }

    function move(address dst, int256 wad) public {
        address src = msg.sender;
        dai[src] = wad > 0
            ? dai[src] - uint256(wad)
            : dai[src] + uint256(-1 * wad);
        dai[dst] = wad > 0
            ? dai[dst] + uint256(wad)
            : dai[dst] - uint256(-1 * wad);
    }

    function frob(int256 dart) public {
        address usr = msg.sender;

        int256 _art = int256(art[usr]) + dart;
        require(_art >= 0, "negative art");
        art[usr] = uint256(_art);

        require(rate <= uint256(type(int256).max), "rate exceeds max int256");
        int256 ddai = dart * int256(rate);

        int256 _dai = int256(dai[usr]) + ddai;
        require(_dai >= 0, "negative dai");
        dai[usr] = uint256(_dai);

        Art = dart > 0 ? Art + uint256(dart) : Art - uint256(-1 * dart);
        debt = ddai > 0 ? debt + uint256(ddai) : debt - uint256(-1 * ddai);
    }

    function fold(int256 delta) public {
        address usr = msg.sender;
        rate = delta > 0 ? rate + uint256(delta) : rate - uint256(-1 * delta);
        require(Art <= uint256(type(int256).max), "Art exceeds max int256");
        int256 ddai = int256(Art) * delta;
        dai[usr] = ddai > 0
            ? dai[usr] + uint256(ddai)
            : dai[usr] - uint256(-1 * ddai);
        debt = ddai > 0 ? debt + uint256(ddai) : debt - uint256(-1 * ddai);
    }
}
