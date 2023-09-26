// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract TotalPrice {

    function totalPriceBuggy(uint96 price, uint32 quantity) public pure returns (uint128) {
        unchecked {
            return uint120(price) * quantity;
        }
    }

    function totalPriceFixed(uint96 price, uint32 quantity) public pure returns (uint128) {
        unchecked {
            return uint128(price) * quantity;
        }
    }

    function totalPriceConservative(uint96 price, uint32 quantity) public pure returns (uint128) {
        unchecked {
            return uint128(uint(price) * uint(quantity));
        }
    }

}
