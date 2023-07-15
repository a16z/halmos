// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract StructTest {
    struct Point {
        uint x;
        uint y;
    }

    // TODO: support struct parameter
    function checkStruct(Point memory) public pure {
        assert(true);
    }
}
