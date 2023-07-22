// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "../src/Example.sol";

/// @custom:halmos --solver-timeout-assertion 0
contract ExampleTest is Example {

    function testTotalPriceBuggy(uint96 price, uint32 quantity) public pure {
        uint128 total = totalPriceBuggy(price, quantity);
        assert(quantity == 0 || total >= price);
    }

    function testTotalPriceFixed(uint96 price, uint32 quantity) public pure {
        uint128 total = totalPriceFixed(price, quantity);
        assert(quantity == 0 || total >= price);
    }

    function testTotalPriceFixedEqualsToConservative(uint96 price, uint32 quantity) public pure {
        uint128 total1 = totalPriceFixed(price, quantity);
        uint128 total2 = totalPriceConservative(price, quantity);
        assert(total1 == total2);
    }

    function testIsPowerOfTwo(uint8 x) public pure {
        bool result1 = isPowerOfTwo(x);
        bool result2 = x == 1 || x == 2 || x == 4 || x == 8 || x == 16 || x == 32 || x == 64 || x == 128;
        assert(result1 == result2);
    }

    /// @custom:halmos --loop 256
    function testIsPowerOfTwo(uint256 x) public pure {
        bool result1 = isPowerOfTwo(x);
        bool result2 = false;
        for (uint i = 0; i < 256; i++) { // NOTE: `--loop 256` option needed for complete verification
            if (x == 2**i) {
                result2 = true;
                break;
            }
        }
        assert(result1 == result2);
    }

    /// @custom:halmos --loop 256
    function testIsPowerOfTwoEq(uint x) public pure {
        bool result1 = isPowerOfTwo(x);
        bool result2 = isPowerOfTwoIter(x);
        assert(result1 == result2);
    }

}
