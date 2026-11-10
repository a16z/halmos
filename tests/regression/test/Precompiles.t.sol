// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

/// @dev regression tests for halmos issue #402: symbolic inputs to the SHA256,
/// RIPEMD160 and MODEXP precompiles used to crash with a z3 sort mismatch
contract PrecompilesTest is Test {
    function modexp(uint256 b, uint256 e, uint256 m) internal view returns (bool ok, uint256 r) {
        bytes memory input = abi.encodePacked(uint256(32), uint256(32), uint256(32), b, e, m);
        bytes memory out;
        (ok, out) = address(5).staticcall(input);
        if (ok && out.length == 32) r = abi.decode(out, (uint256));
    }

    //
    // sha256
    //

    function check_sha256_concrete() public pure {
        assertEq(sha256(""), 0xe3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855);
        assertEq(sha256("abc"), 0xba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad);
    }

    function check_sha256_symbolic(uint256 x, uint256 y) public pure {
        vm.assume(x == y);
        assertEq(sha256(abi.encode(x)), sha256(abi.encode(y)));
    }

    function check_sha256_symbolic_fail(uint256 x, uint256 y) public pure {
        // uninterpreted: dolmos can't rule out a collision
        assertTrue(sha256(abi.encode(x)) != sha256(abi.encode(y)));
    }

    //
    // ripemd160
    //

    function check_ripemd160_concrete() public pure {
        assertEq(ripemd160(""), bytes20(hex"9c1185a5c5e9fc54612808977ee8f548b2258d31"));
        assertEq(ripemd160("abc"), bytes20(hex"8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"));
    }

    function check_ripemd160_symbolic(uint256 x, uint256 y) public pure {
        vm.assume(x == y);
        assertEq(ripemd160(abi.encode(x)), ripemd160(abi.encode(y)));
    }

    //
    // modexp
    //

    function check_modexp_concrete() public view {
        (bool ok, uint256 r) = modexp(3, 5, 7);
        assertTrue(ok);
        assertEq(r, 5); // 243 % 7
    }

    function check_modexp_mod_zero(uint256 b, uint256 e) public view {
        (bool ok, uint256 r) = modexp(b, e, 0);
        assertTrue(ok);
        assertEq(r, 0);
    }

    function check_modexp_exp_zero(uint256 b, uint256 m) public view {
        vm.assume(m > 1);
        (bool ok, uint256 r) = modexp(b, 0, m);
        assertTrue(ok);
        assertEq(r, 1);
    }

    function check_modexp_symbolic(uint256 b, uint256 e, uint256 m) public view {
        vm.assume(m != 0);
        (bool ok, uint256 r) = modexp(b, e, m);
        assertTrue(ok);
        assertLt(r, m);
    }

    function check_modexp_symbolic_fail(uint256 b, uint256 e, uint256 m) public view {
        vm.assume(m > 2);
        (, uint256 r) = modexp(b, e, m);
        assertEq(r, 1); // counterexample expected
    }

    function check_modexp_short_input() public view {
        // missing bytes are zeros: base = 2, exponent = 3, modulus = 0x05 << 8
        (bool ok, bytes memory out) = address(5).staticcall(
            abi.encodePacked(uint256(1), uint256(1), uint256(2), uint8(2), uint8(3), uint8(5))
        );
        assertTrue(ok);
        assertEq(out.length, 2);
        assertEq(uint16(bytes2(out)), 8);
    }

    function check_modexp_empty_modulus(uint256 b, uint256 e) public view {
        (bool ok, bytes memory out) =
            address(5).staticcall(abi.encodePacked(uint256(32), uint256(32), uint256(0), b, e));
        assertTrue(ok);
        assertEq(out.length, 0);
    }

    function check_modexp_oversized_input() public view {
        // EIP-7823: length fields above 1024 bytes make the precompile fail
        (bool ok,) = address(5).staticcall(abi.encodePacked(uint256(1025), uint256(1), uint256(1)));
        assertFalse(ok);
    }
}
