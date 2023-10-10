// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

// no hop
contract X {
    function foo() internal {
        assembly {
            selfdestruct(0) // unsupported opcode
        }
    }

    function check_unsupported_opcode() public {
        foo(); // unsupported error
    }
}

// 1 hop
contract Y {
    X x;

    function setUp() public {
        x = new X();
    }

    function check_unsupported_opcode() public {
        x.check_unsupported_opcode(); // unsupported error
    }
}

// 2 hops
contract Z {
    Y y;

    function setUp() public {
        y = new Y();
        y.setUp();
    }

    function check_unsupported_opcode() public {
        y.check_unsupported_opcode(); // unsupported error
    }
}
