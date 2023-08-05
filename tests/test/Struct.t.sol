// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract StructTest {
    struct Point {
        uint x;
        uint y;
    }

    function check_Struct(Point memory p) public pure {
        assert(true);
    }

    function check_StructArray(Point[] memory p, Point[2] memory q) public pure {
        assert(true);
    }

    function check_StructArrayArray(
        Point[][] memory p,
        Point[3][] memory q,
        Point[][5] memory r,
        Point[7][9] memory s
    ) public pure {
        assert(true);
    }
}
