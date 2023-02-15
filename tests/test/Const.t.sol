// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/Const.sol";

contract ConstTest is Const {
    function testConst() public {
        assert(const == 11);
    }
}

contract ConstTestTest is Const, Test {
    function testConst() public {
        assertEq(const, 11);
    }
}
