// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

/// Precompiles that are modeled as uninterpreted functions over symbolic input.
/// The function input sorts must be sized in bits (input byte length * 8).
contract PrecompileTest is Test {
    function check_sha256_symbolic(bytes32 x, bytes32 y) public view {
        assertEq(sha256(abi.encode(x, y)), sha256(abi.encode(x, y)));
    }

    function check_ripemd160_symbolic(bytes32 x, bytes32 y) public view {
        assertEq(ripemd160(abi.encode(x, y)), ripemd160(abi.encode(x, y)));
    }

    function check_modexp_symbolic(uint256 base, uint256 exp, uint256 mod) public view {
        // base_len, exp_len, mod_len are all 32 bytes
        bytes memory input = abi.encode(uint256(32), uint256(32), uint256(32), base, exp, mod);

        (bool success, bytes memory retdata) = address(0x05).staticcall(input);

        assertTrue(success);
        assertEq(retdata.length, 32); // mod_len bytes
    }
}
