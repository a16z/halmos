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

    // if setUpSymbolic() is provided, Halmos uses setUpSymbolic() instead of setUp().
    // setUpSymbolic() is symbolically executed.

    // if multiple setUpSymbolic() functions are provided, the last one in the lexicographical order will be used.
    // e.g., setUpSymbolic(uint256,uint256) is used instead of setUpSymbolic(uint256).

    function setUpSymbolic(uint x, uint y) public {
        require(x > 10);
        require(y > 100);
        a = new A(x, y);
    }

    function setUpSymbolic(uint x) public {
        a = new A(x, x);
    }

    function check_Setup() public view {
        assert(a.x() > 10);
        assert(a.y() > 100);
    }
}

contract B {
    uint public x1;
    uint public y1;
    uint public x2;
    uint public y2;

    struct S {
        uint a;
        uint b;
    }

    constructor(S[] memory lst) {
        require(lst.length >= 2);
        x1 = lst[0].a;
        y1 = lst[0].b;
        x2 = lst[1].a;
        y2 = lst[1].b;
    }
}

contract SetupPlusTestB {
    B b;
    uint[4] init;

    function mk() public {
        B.S[] memory lst = new B.S[](2);
        lst[0] = B.S(init[0], init[1]);
        lst[1] = B.S(init[2], init[3]);
        b = new B(lst);
    }

    function setUp() public {
        init[0] = 10;
        init[1] = 20;
        init[2] = 30;
        init[3] = 40;
        mk();
    }

    function setUpSymbolic(uint[4] memory _init) public {
        init[0] = _init[0];
        init[1] = _init[1];
        init[2] = _init[2];
        init[3] = _init[3];
        mk();
    }

    function check_Setup() public view {
        assert(b.x1() == init[0]);
        assert(b.y1() == init[1]);
        assert(b.x2() == init[2]);
        assert(b.y2() == init[3]);
    }
}
