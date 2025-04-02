// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract C {
    uint public num;
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function inc() external {
        require(msg.sender == owner);
        num++;
    }
}

abstract contract InvariantSenderTest is Test {
    C c;

    function invariant_num() public {
        assertEq(c.num(), 0);
    }
}

contract InvariantSenderTest_non_owner_1 is InvariantSenderTest {
    function setUp() public {
        c = new C();

        targetSender(address(0xbeef));
    }
}

contract InvariantSenderTest_non_owner_2 is InvariantSenderTest {
    function setUp() public {
        c = new C();

        targetSender(address(0xdead));
        targetSender(address(0xbeef));
    }
}

contract InvariantSenderTest_owner is InvariantSenderTest {
    function setUp() public {
        c = new C();

        targetSender(address(this));
    }
}

contract InvariantSenderTest_all is InvariantSenderTest {
    function setUp() public {
        c = new C();
    }
}
