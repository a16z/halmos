// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "src/Example.sol";

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

}
