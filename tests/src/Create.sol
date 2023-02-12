// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract Create {
    uint public value;
    uint public immutable halmos;
    uint public initialized = 7;
    uint public constant const = 11;

    constructor(uint qed) {
        halmos = qed;
    }

    function set(uint x) public {
        value = x;
    }
}
