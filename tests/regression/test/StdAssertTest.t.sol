// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract StdAssertPassTest is Test {
    function setUp() public {
    }

    function check_assertTrue(bool b) public {
        vm.assume(b);
        assertTrue(b);
    }

    function check_assertFalse(bool b) public {
        vm.assume(!b);
        assertFalse(b);
    }

    function check_assertEq(bool x, bool y) public {
        vm.assume(x == y);
        assertEq(x, y);
    }

    function check_assertEq(uint x, uint y) public {
        vm.assume(x == y);
        assertEq(x, y);
    }

    function check_assertEq(int x, int y) public {
        vm.assume(x == y);
        assertEq(x, y);
    }

    function check_assertEq(address x, address y) public {
        vm.assume(x == y);
        assertEq(x, y);
    }

    function check_assertEq(bytes32 x, bytes32 y) public {
        vm.assume(x == y);
        assertEq(x, y);
    }

    function check_assertEq(string memory x, string memory y) public {
        vm.assume(keccak256(bytes(x)) == keccak256(bytes(y)));
        assertEq(x, y);
    }

    function check_assertEq(bytes memory x, bytes memory y) public {
        vm.assume(keccak256(x) == keccak256(y));
        assertEq(x, y);
    }

    function check_assertEq(bool[] memory x, bool[] memory y) public {
        vm.assume(keccak256(abi.encode(x)) == keccak256(abi.encode(y)));
        assertEq(x, y);
    }

    function check_assertEq(uint[] memory x, uint[] memory y) public {
        vm.assume(keccak256(abi.encode(x)) == keccak256(abi.encode(y)));
        assertEq(x, y);
    }

    function check_assertEq(int[] memory x, int[] memory y) public {
        vm.assume(keccak256(abi.encode(x)) == keccak256(abi.encode(y)));
        assertEq(x, y);
    }

    function check_assertEq(address[] memory x, address[] memory y) public {
        vm.assume(keccak256(abi.encode(x)) == keccak256(abi.encode(y)));
        assertEq(x, y);
    }

    function check_assertEq(bytes32[] memory x, bytes32[] memory y) public {
        vm.assume(keccak256(abi.encode(x)) == keccak256(abi.encode(y)));
        assertEq(x, y);
    }

    /* TODO:
    function check_assertEq(string[] memory x, string[] memory y) public {
        vm.assume(keccak256(abi.encode(x)) == keccak256(abi.encode(y)));
        assertEq(x, y);
    }

    function check_assertEq(bytes[] memory x, bytes[] memory y) public {
        vm.assume(keccak256(abi.encode(x)) == keccak256(abi.encode(y)));
        assertEq(x, y);
    }
    */

    function check_assertNotEq(bool x, bool y) public {
        vm.assume(x != y);
        assertNotEq(x, y);
    }

    function check_assertNotEq(uint x, uint y) public {
        vm.assume(x != y);
        assertNotEq(x, y);
    }

    function check_assertNotEq(int x, int y) public {
        vm.assume(x != y);
        assertNotEq(x, y);
    }

    function check_assertNotEq(address x, address y) public {
        vm.assume(x != y);
        assertNotEq(x, y);
    }

    function check_assertNotEq(bytes32 x, bytes32 y) public {
        vm.assume(x != y);
        assertNotEq(x, y);
    }

    function check_assertNotEq(string memory x, string memory y) public {
        vm.assume(keccak256(bytes(x)) != keccak256(bytes(y)));
        assertNotEq(x, y);
    }

    function check_assertNotEq(bytes memory x, bytes memory y) public {
        vm.assume(keccak256(x) != keccak256(y));
        assertNotEq(x, y);
    }

    function check_assertNotEq(bool[] memory x, bool[] memory y) public {
        vm.assume(keccak256(abi.encode(x)) != keccak256(abi.encode(y)));
        assertNotEq(x, y);
    }

    function check_assertNotEq(uint[] memory x, uint[] memory y) public {
        vm.assume(keccak256(abi.encode(x)) != keccak256(abi.encode(y)));
        assertNotEq(x, y);
    }

    function check_assertNotEq(int[] memory x, int[] memory y) public {
        vm.assume(keccak256(abi.encode(x)) != keccak256(abi.encode(y)));
        assertNotEq(x, y);
    }

    function check_assertNotEq(address[] memory x, address[] memory y) public {
        vm.assume(keccak256(abi.encode(x)) != keccak256(abi.encode(y)));
        assertNotEq(x, y);
    }

    function check_assertNotEq(bytes32[] memory x, bytes32[] memory y) public {
        vm.assume(keccak256(abi.encode(x)) != keccak256(abi.encode(y)));
        assertNotEq(x, y);
    }

    /* TODO:
    function check_assertNotEq(string[] memory x, string[] memory y) public {
        vm.assume(keccak256(abi.encode(x)) != keccak256(abi.encode(y)));
        assertNotEq(x, y);
    }

    function check_assertNotEq(bytes[] memory x, bytes[] memory y) public {
        vm.assume(keccak256(abi.encode(x)) != keccak256(abi.encode(y)));
        assertNotEq(x, y);
    }
    */

    function check_assertLt(uint x, uint y) public {
        vm.assume(x < y);
        assertLt(x, y);
    }

    function check_assertGt(uint x, uint y) public {
        vm.assume(x > y);
        assertGt(x, y);
    }

    function check_assertLe(uint x, uint y) public {
        vm.assume(x <= y);
        assertLe(x, y);
    }

    function check_assertGe(uint x, uint y) public {
        vm.assume(x >= y);
        assertGe(x, y);
    }

    function check_assertLt(int x, int y) public {
        vm.assume(x < y);
        assertLt(x, y);
    }

    function check_assertGt(int x, int y) public {
        vm.assume(x > y);
        assertGt(x, y);
    }

    function check_assertLe(int x, int y) public {
        vm.assume(x <= y);
        assertLe(x, y);
    }

    function check_assertGe(int x, int y) public {
        vm.assume(x >= y);
        assertGe(x, y);
    }
}

contract StdAssertFailTest is Test {
    function setUp() public {
    }

    function check_assertTrue(bool b) public {
        vm.assume(!b);
        assertTrue(b);
    }

    function check_assertFalse(bool b) public {
        vm.assume(!(!b));
        assertFalse(b);
    }

    function check_assertEq(bool x, bool y) public {
        vm.assume(!(x == y));
        assertEq(x, y);
    }

    function check_assertEq(uint x, uint y) public {
        vm.assume(!(x == y));
        assertEq(x, y);
    }

    function check_assertEq(int x, int y) public {
        vm.assume(!(x == y));
        assertEq(x, y);
    }

    function check_assertEq(address x, address y) public {
        vm.assume(!(x == y));
        assertEq(x, y);
    }

    function check_assertEq(bytes32 x, bytes32 y) public {
        vm.assume(!(x == y));
        assertEq(x, y);
    }

    function check_assertEq(string memory x, string memory y) public {
        vm.assume(!(keccak256(bytes(x)) == keccak256(bytes(y))));
        assertEq(x, y);
    }

    function check_assertEq(bytes memory x, bytes memory y) public {
        vm.assume(!(keccak256(x) == keccak256(y)));
        assertEq(x, y);
    }

    function check_assertEq(bool[] memory x, bool[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) == keccak256(abi.encode(y))));
        assertEq(x, y);
    }

    function check_assertEq(uint[] memory x, uint[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) == keccak256(abi.encode(y))));
        assertEq(x, y);
    }

    function check_assertEq(int[] memory x, int[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) == keccak256(abi.encode(y))));
        assertEq(x, y);
    }

    function check_assertEq(address[] memory x, address[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) == keccak256(abi.encode(y))));
        assertEq(x, y);
    }

    function check_assertEq(bytes32[] memory x, bytes32[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) == keccak256(abi.encode(y))));
        assertEq(x, y);
    }

    /* TODO:
    function check_assertEq(string[] memory x, string[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) == keccak256(abi.encode(y))));
        assertEq(x, y);
    }

    function check_assertEq(bytes[] memory x, bytes[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) == keccak256(abi.encode(y))));
        assertEq(x, y);
    }
    */

    function check_assertNotEq(bool x, bool y) public {
        vm.assume(!(x != y));
        assertNotEq(x, y);
    }

    function check_assertNotEq(uint x, uint y) public {
        vm.assume(!(x != y));
        assertNotEq(x, y);
    }

    function check_assertNotEq(int x, int y) public {
        vm.assume(!(x != y));
        assertNotEq(x, y);
    }

    function check_assertNotEq(address x, address y) public {
        vm.assume(!(x != y));
        assertNotEq(x, y);
    }

    function check_assertNotEq(bytes32 x, bytes32 y) public {
        vm.assume(!(x != y));
        assertNotEq(x, y);
    }

    function check_assertNotEq(string memory x, string memory y) public {
        vm.assume(!(keccak256(bytes(x)) != keccak256(bytes(y))));
        assertNotEq(x, y);
    }

    function check_assertNotEq(bytes memory x, bytes memory y) public {
        vm.assume(!(keccak256(x) != keccak256(y)));
        assertNotEq(x, y);
    }

    function check_assertNotEq(bool[] memory x, bool[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) != keccak256(abi.encode(y))));
        assertNotEq(x, y);
    }

    function check_assertNotEq(uint[] memory x, uint[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) != keccak256(abi.encode(y))));
        assertNotEq(x, y);
    }

    function check_assertNotEq(int[] memory x, int[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) != keccak256(abi.encode(y))));
        assertNotEq(x, y);
    }

    function check_assertNotEq(address[] memory x, address[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) != keccak256(abi.encode(y))));
        assertNotEq(x, y);
    }

    function check_assertNotEq(bytes32[] memory x, bytes32[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) != keccak256(abi.encode(y))));
        assertNotEq(x, y);
    }

    /* TODO:
    function check_assertNotEq(string[] memory x, string[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) != keccak256(abi.encode(y))));
        assertNotEq(x, y);
    }

    function check_assertNotEq(bytes[] memory x, bytes[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) != keccak256(abi.encode(y))));
        assertNotEq(x, y);
    }
    */

    function check_assertLt(uint x, uint y) public {
        vm.assume(!(x < y));
        assertLt(x, y);
    }

    function check_assertGt(uint x, uint y) public {
        vm.assume(!(x > y));
        assertGt(x, y);
    }

    function check_assertLe(uint x, uint y) public {
        vm.assume(!(x <= y));
        assertLe(x, y);
    }

    function check_assertGe(uint x, uint y) public {
        vm.assume(!(x >= y));
        assertGe(x, y);
    }

    function check_assertLt(int x, int y) public {
        vm.assume(!(x < y));
        assertLt(x, y);
    }

    function check_assertGt(int x, int y) public {
        vm.assume(!(x > y));
        assertGt(x, y);
    }

    function check_assertLe(int x, int y) public {
        vm.assume(!(x <= y));
        assertLe(x, y);
    }

    function check_assertGe(int x, int y) public {
        vm.assume(!(x >= y));
        assertGe(x, y);
    }
}

contract StdAssertFailLogTest is Test {
    function setUp() public {
    }

    function check_assertTrue(bool b) public {
        vm.assume(!b);
        assertTrue(b, "");
    }

    function check_assertFalse(bool b) public {
        vm.assume(!(!b));
        assertFalse(b, "");
    }

    function check_assertEq(bool x, bool y) public {
        vm.assume(!(x == y));
        assertEq(x, y, "");
    }

    function check_assertEq(uint x, uint y) public {
        vm.assume(!(x == y));
        assertEq(x, y, "");
    }

    function check_assertEq(int x, int y) public {
        vm.assume(!(x == y));
        assertEq(x, y, "");
    }

    function check_assertEq(address x, address y) public {
        vm.assume(!(x == y));
        assertEq(x, y, "");
    }

    function check_assertEq(bytes32 x, bytes32 y) public {
        vm.assume(!(x == y));
        assertEq(x, y, "");
    }

    function check_assertEq(string memory x, string memory y) public {
        vm.assume(!(keccak256(bytes(x)) == keccak256(bytes(y))));
        assertEq(x, y, "");
    }

    function check_assertEq(bytes memory x, bytes memory y) public {
        vm.assume(!(keccak256(x) == keccak256(y)));
        assertEq(x, y, "");
    }

    function check_assertEq(bool[] memory x, bool[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) == keccak256(abi.encode(y))));
        assertEq(x, y, "");
    }

    function check_assertEq(uint[] memory x, uint[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) == keccak256(abi.encode(y))));
        assertEq(x, y, "");
    }

    function check_assertEq(int[] memory x, int[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) == keccak256(abi.encode(y))));
        assertEq(x, y, "");
    }

    function check_assertEq(address[] memory x, address[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) == keccak256(abi.encode(y))));
        assertEq(x, y, "");
    }

    function check_assertEq(bytes32[] memory x, bytes32[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) == keccak256(abi.encode(y))));
        assertEq(x, y, "");
    }

    /* TODO:
    function check_assertEq(string[] memory x, string[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) == keccak256(abi.encode(y))));
        assertEq(x, y, "");
    }

    function check_assertEq(bytes[] memory x, bytes[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) == keccak256(abi.encode(y))));
        assertEq(x, y, "");
    }
    */

    function check_assertNotEq(bool x, bool y) public {
        vm.assume(!(x != y));
        assertNotEq(x, y, "");
    }

    function check_assertNotEq(uint x, uint y) public {
        vm.assume(!(x != y));
        assertNotEq(x, y, "");
    }

    function check_assertNotEq(int x, int y) public {
        vm.assume(!(x != y));
        assertNotEq(x, y, "");
    }

    function check_assertNotEq(address x, address y) public {
        vm.assume(!(x != y));
        assertNotEq(x, y, "");
    }

    function check_assertNotEq(bytes32 x, bytes32 y) public {
        vm.assume(!(x != y));
        assertNotEq(x, y, "");
    }

    function check_assertNotEq(string memory x, string memory y) public {
        vm.assume(!(keccak256(bytes(x)) != keccak256(bytes(y))));
        assertNotEq(x, y, "");
    }

    function check_assertNotEq(bytes memory x, bytes memory y) public {
        vm.assume(!(keccak256(x) != keccak256(y)));
        assertNotEq(x, y, "");
    }

    function check_assertNotEq(bool[] memory x, bool[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) != keccak256(abi.encode(y))));
        assertNotEq(x, y, "");
    }

    function check_assertNotEq(uint[] memory x, uint[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) != keccak256(abi.encode(y))));
        assertNotEq(x, y, "");
    }

    function check_assertNotEq(int[] memory x, int[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) != keccak256(abi.encode(y))));
        assertNotEq(x, y, "");
    }

    function check_assertNotEq(address[] memory x, address[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) != keccak256(abi.encode(y))));
        assertNotEq(x, y, "");
    }

    function check_assertNotEq(bytes32[] memory x, bytes32[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) != keccak256(abi.encode(y))));
        assertNotEq(x, y, "");
    }

    /* TODO:
    function check_assertNotEq(string[] memory x, string[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) != keccak256(abi.encode(y))));
        assertNotEq(x, y, "");
    }

    function check_assertNotEq(bytes[] memory x, bytes[] memory y) public {
        vm.assume(!(keccak256(abi.encode(x)) != keccak256(abi.encode(y))));
        assertNotEq(x, y, "");
    }
    */

    function check_assertLt(uint x, uint y) public {
        vm.assume(!(x < y));
        assertLt(x, y, "");
    }

    function check_assertGt(uint x, uint y) public {
        vm.assume(!(x > y));
        assertGt(x, y, "");
    }

    function check_assertLe(uint x, uint y) public {
        vm.assume(!(x <= y));
        assertLe(x, y, "");
    }

    function check_assertGe(uint x, uint y) public {
        vm.assume(!(x >= y));
        assertGe(x, y, "");
    }

    function check_assertLt(int x, int y) public {
        vm.assume(!(x < y));
        assertLt(x, y, "");
    }

    function check_assertGt(int x, int y) public {
        vm.assume(!(x > y));
        assertGt(x, y, "");
    }

    function check_assertLe(int x, int y) public {
        vm.assume(!(x <= y));
        assertLe(x, y, "");
    }

    function check_assertGe(int x, int y) public {
        vm.assume(!(x >= y));
        assertGe(x, y, "");
    }
}
