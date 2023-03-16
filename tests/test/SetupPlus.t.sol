// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract A {
    uint public immutable x;
    uint public y;

    constructor(uint _x, uint _y) {
        x = _x;
        y = _y;
    }
}

contract SetupPlusTest {
    A a;

    function setUp() public {
        a = new A(11, 200);
    }

    // if setUpPlus() is provided, Halmos uses setUpPlus() instead of setUp().
    // setUpPlus() is symbolically executed.

    // if multiple setUpPlus() functions are provided, the last one in the lexicographical order will be used.
    // e.g., setUpPlus(uint256,uint256) is used instead of setUpPlus(uint256).

    function setUpPlus(uint x, uint y) public {
        require(x > 10);
        require(y > 100);
        a = new A(x, y);
    }

    function setUpPlus(uint x) public {
        a = new A(x, x);
    }

    function testSetup() public {
        assert(a.x() > 10);
        assert(a.y() > 100);
    }
}
