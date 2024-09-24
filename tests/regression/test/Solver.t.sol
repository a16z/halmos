// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract SolverTest is SymTest, Test {
    uint[] numbers;

    function check_dynamic_array_overflow() public {
        numbers = new uint[](5); // shouldn't generate loop bounds warning
    }
}
