// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract X {
    function foo() public {
        assembly {
            selfdestruct(0) // unsupported opcode
        }
    }

    function checkFoo() public {
        foo(); // unsupported error
    }
}

contract Y {
    X x;

    function setUp() public {
        x = new X();
    }

    function checkFoo() public {
        x.foo(); // unsupported error
    }
}

contract Z {
    Y y;

    function setUp() public {
        y = new Y();
        y.setUp();
    }

    function checkFoo() public {
        y.checkFoo(); // unsupported error
    }
}
