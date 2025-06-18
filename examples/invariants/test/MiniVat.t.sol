// SPDX-License-Identifier: AGPL-3.0-or-later
pragma solidity ^0.8.13;

/// @notice from https://github.com/aviggiano/property-based-testing-benchmark/blob/main/projects/dai-certora/test/TargetFunctions.sol

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

import {MiniVat} from "../src/MiniVat.sol";

/// @custom:halmos --early-exit
contract MiniVatTest is Test, SymTest {
    MiniVat public minivat;

    function setUp() public {
        minivat = new MiniVat();
    }

    function invariant_dai() public {
        assertEq(
            minivat.debt(),
            minivat.Art() * minivat.rate(),
            "The Fundamental Equation of DAI"
        );
    }
}
