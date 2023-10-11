// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract List {
    uint[] public arr;

    constructor() { }

    function size() public view returns (uint) {
        return arr.length;
    }

    function add(uint x) public {
        arr.push(x);
    }

    function remove() public {
        arr.pop();
    }

    function set(uint i, uint x) public {
        arr[i] = x;
    }
}
