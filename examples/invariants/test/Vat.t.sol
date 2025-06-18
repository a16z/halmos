// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

import {Vat} from "../src/Vat.sol";

/// @custom:halmos --early-exit
contract VatTest is Test {
    Vat public vat;
    bytes32 ilk;

    function setUp() public {
        vat = new Vat();
        ilk = "gems";

        vat.init(ilk);
    }

    function invariant_dai() public view {
        assertEq(
            vat.debt(),
            vat.vice() + vat.Art(ilk) * vat.rate(ilk),
            "The Fundamental Equation of DAI"
        );
    }
}
