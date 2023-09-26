// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "../src/TotalPrice.sol";

/// @custom:halmos --solver-timeout-assertion 0
contract TotalPriceTest {
    TotalPrice target;

    function setUp() public {
        target = new TotalPrice();
    }

    function check_totalPriceBuggy(uint96 price, uint32 quantity) public view {
        uint128 total = target.totalPriceBuggy(price, quantity);
        assert(quantity == 0 || total >= price);
    }

    function check_totalPriceFixed(uint96 price, uint32 quantity) public view {
        uint128 total = target.totalPriceFixed(price, quantity);
        assert(quantity == 0 || total >= price);
    }

    function check_eq_totalPriceFixed_totalPriceConservative(uint96 price, uint32 quantity) public view {
        uint128 total1 = target.totalPriceFixed(price, quantity);
        uint128 total2 = target.totalPriceConservative(price, quantity);
        assert(total1 == total2);
    }
}
