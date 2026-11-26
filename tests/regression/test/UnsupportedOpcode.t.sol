// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

// no hop
contract X {
    function foo() internal {
        assembly {
            // deploy a contract whose runtime code is the undefined opcode 0x0c, and call it
            // initcode: PUSH1 0x0c PUSH0 MSTORE8 PUSH1 0x01 PUSH0 RETURN
            mstore(0, shl(192, 0x600c5f5360015ff3))
            let target := create(0, 0, 8)
            pop(call(gas(), target, 0, 0, 0, 0, 0)) // unsupported opcode
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
