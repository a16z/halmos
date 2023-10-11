// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract SetupTest is Test {
    address[] public users;
    uint256 public constant size = 3;

    function setUp() public {
        users = new address[](size);
        users[0] = address(bytes20(keccak256("test")));
        for (uint256 i = 1; i < size - 1; i++) {
            users[i] = address(uint160(users[i - 1]) + 1);
        }
    }

    function check_True() public {
        assertEq(users[0], address(bytes20(keccak256("test"))));
        assertEq(users[1], address(uint160(users[0]) + 1));
        assertEq(users[2], address(0));
    }
}

contract SetupFailTest {
    function setUp() public {
        revert();
    }

    function check_setUp_Fail1() public {
        assert(true);
    }

    function check_setUp_Fail2() public {
        assert(true);
    }
}
