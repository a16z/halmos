// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

address constant user1 = address(0x11);
address constant user2 = address(0x22);
address constant user3 = address(0x33);

contract C {
    uint public num1;
    uint public num2;
    uint public num3;

    constructor() {
    }

    function inc1() external {
        require(msg.sender == user1);
        num1++;
    }

    function inc2() external {
        require(msg.sender == user2);
        num2++;
    }

    function inc3() external {
        require(msg.sender == user3);
        num3++;
    }
}

abstract contract InvariantSenderTest is Test {
    C c;

    function invariant_num1() public {
        assertEq(c.num1(), 0);
    }

    function invariant_num2() public {
        assertEq(c.num2(), 0);
    }

    function invariant_num3() public {
        assertEq(c.num3(), 0);
    }
}

contract InvariantSenderTest_excludeSender_empty is InvariantSenderTest {
    function setUp() public {
        c = new C();

        // sender: *
    }
}

contract InvariantSenderTest_excludeSender_0 is InvariantSenderTest {
    function setUp() public {
        c = new C();

        targetSender(user1);

        excludeSender(user1);

        // sender: * - {user1}
    }
}

contract InvariantSenderTest_excludeSender_1 is InvariantSenderTest {
    function setUp() public {
        c = new C();

        targetSender(user1);

        targetSender(user2);

        excludeSender(user2);

        // sender: {user1}
    }
}

contract InvariantSenderTest_excludeSender_2 is InvariantSenderTest {
    function setUp() public {
        c = new C();

        targetSender(user1);

        excludeSender(user2);

        targetSender(user2);

        // sender: {user1}
    }
}

contract InvariantSenderTest_excludeSender_3 is InvariantSenderTest {
    function setUp() public {
        c = new C();

        targetSender(user1);

        excludeSender(user1);

        excludeSender(user2);

        // sender: * - {user1, user2}
    }
}
