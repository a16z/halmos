// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

/// vm.toString (halmos#565), with foundry's formatting
contract ToStringTest is Test {
    function eq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    function isHexDigit(bytes1 c) internal pure returns (bool) {
        return (c >= "0" && c <= "9") || (c >= "a" && c <= "f");
    }

    function check_toString_concrete() public pure {
        // EIP-55 checksum
        assert(eq(vm.toString(address(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D)), "0x7109709ECfa91a80626fF3989D68f67F5b1DD12D"));
        assert(eq(vm.toString(address(0)), "0x0000000000000000000000000000000000000000"));

        assert(eq(vm.toString(bytes32(uint256(0xabc))), "0x0000000000000000000000000000000000000000000000000000000000000abc"));
        assert(eq(vm.toString(bytes(hex"00ff10")), "0x00ff10"));
        assert(eq(vm.toString(bytes(hex"")), "0x"));

        assert(eq(vm.toString(true), "true"));
        assert(eq(vm.toString(false), "false"));

        assert(eq(vm.toString(uint256(0)), "0"));
        assert(eq(vm.toString(uint256(1234)), "1234"));
        assert(eq(vm.toString(type(uint256).max), "115792089237316195423570985008687907853269984665640564039457584007913129639935"));

        assert(eq(vm.toString(int256(-42)), "-42"));
        assert(eq(vm.toString(int256(7)), "7"));
        assert(eq(vm.toString(type(int256).min), "-57896044618658097711785492504343953926634992332820282019728792003956564819968"));
    }

    function check_toString_bytes32(bytes32 x) public pure {
        bytes memory s = bytes(vm.toString(x));
        assert(s.length == 66);
        assert(s[0] == "0" && s[1] == "x");
        assert(isHexDigit(s[2]) && isHexDigit(s[33]) && isHexDigit(s[65]));
        // the first digit is the high nibble of x
        if (uint256(x) >> 252 == 0xa) assert(s[2] == "a");
        if (uint256(x) >> 252 == 0x3) assert(s[2] == "3");
    }

    function check_toString_bytes(bytes4 x) public pure {
        bytes memory s = bytes(vm.toString(abi.encodePacked(x)));
        assert(s.length == 10);
        if (x == 0xdeadbeef) assert(eq(string(s), "0xdeadbeef"));
    }

    function check_toString_bool(bool b) public pure {
        // one path per value, since the strings differ in length
        string memory s = vm.toString(b);
        assert(eq(s, b ? "true" : "false"));
    }

    function check_toString_bool_fail(bool b) public pure {
        // fails for b == false only
        assert(bytes(vm.toString(b)).length == 4);
    }

    function check_toString_address(address a) public pure {
        bytes memory s = bytes(vm.toString(a));
        assert(s.length == 42);
        assert(s[0] == "0" && s[1] == "x");
        // the digits are exact, only the case of the letters is approximated
        if (uint160(a) >> 156 == 0x1) assert(s[2] == "1");
        if (uint160(a) >> 156 == 0xb) assert(s[2] == "b" || s[2] == "B");
    }

    function check_toString_uint(uint256 x) public pure {
        // approximated: a string of digits
        bytes memory s = bytes(vm.toString(x));
        assert(s.length > 0);
        assert(s[0] >= "0" && s[0] <= "9");
    }

    /// the scenario of halmos#565: forge-std's bound(int256, ...) logs its result
    function check_bound_int(int256 x) public {
        int256 y = bound(x, -10, 10);
        assert(y >= -10 && y <= 10);
    }
}
