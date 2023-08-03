// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract TestConstructorTest {
    uint public value = 1;
    uint constant const = 2;

    function check_value() public view {
        assert(value == 1);
        assert(const == 2);
    }
}
