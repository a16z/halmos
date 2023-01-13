// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract Example {

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

    function isPowerOfTwo(uint x) public pure returns (bool) {
        unchecked {
            return x != 0 && (x & (x - 1)) == 0;
        }
    }

    function isPowerOfTwoIter(uint x) public pure returns (bool) {
        unchecked {
            while (x != 0 && (x & 1) == 0) x >>= 1;
            return x == 1;
        }
    }

}
