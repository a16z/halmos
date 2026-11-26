// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

/// @dev deploys `runtime` as is, to run opcode sequences that solc doesn't emit
contract RawCode {
    constructor(bytes memory runtime) {
        assembly {
            return(add(runtime, 32), mload(runtime))
        }
    }
}

/// @dev EVM semantics inherited from halmos (halmos#593, #594, #596, #597).
/// The runtimes are written by hand, so that the compiler can't fold or rewrite the opcodes
/// under test; each one is commented with its disassembly.
contract EvmSemanticsTest is Test {
    function deploy(bytes memory runtime) internal returns (address) {
        return address(new RawCode(runtime));
    }

    function callWord(address target, bytes memory data) internal returns (bool ok, uint256 word) {
        bytes memory ret;
        (ok, ret) = target.call(data);
        if (ok) word = abi.decode(ret, (uint256));
    }

    /// halmos#593: NOT complements the 256 bits of a comparison result

    function check_not_of_eq(uint256 a, uint256 b) public {
        // PUSH1 0 CALLDATALOAD PUSH1 32 CALLDATALOAD EQ NOT; return the word
        address target = deploy(hex"600035602035141960005260206000f3");
        (bool ok, uint256 r) = callWord(target, abi.encode(a, b));
        assert(ok);
        assertEq(r, a == b ? type(uint256).max - 1 : type(uint256).max);
    }

    function check_not_of_iszero(uint256 a) public {
        // PUSH1 0 CALLDATALOAD ISZERO NOT; return the word
        address target = deploy(hex"600035151960005260206000f3");
        (bool ok, uint256 r) = callWord(target, abi.encode(a));
        assert(ok);
        assertEq(r, a == 0 ? type(uint256).max - 1 : type(uint256).max);
    }

    /// halmos#594: a JUMPI to an invalid destination only halts when the jump is taken

    function check_jumpi_invalid_target(uint256 cond) public {
        // PUSH1 0 CALLDATALOAD PUSH1 0xff JUMPI STOP (0xff is not a JUMPDEST)
        address target = deploy(hex"60003560ff5700");
        (bool ok,) = target.call(abi.encode(cond));
        assert(ok == (cond == 0));
    }

    /// halmos#596: RETURNDATACOPY checks its bounds even when it copies nothing

    function check_returndatacopy_zero_size_out_of_bounds() public {
        // RETURNDATACOPY(destOffset: 0, offset: 1, size: 0) with empty return data
        address target = deploy(hex"6000600160003e00");
        (bool ok,) = target.call("");
        assert(!ok);
    }

    function check_returndatacopy_zero_size_in_bounds() public {
        // RETURNDATACOPY(destOffset: 0, offset: 0, size: 0) with empty return data
        address target = deploy(hex"6000600060003e00");
        (bool ok,) = target.call("");
        assert(ok);
    }

    /// halmos#597: memory reads expand the active memory reported by MSIZE

    function check_msize_after_mload() public {
        // PUSH1 0x40 MLOAD POP MSIZE; return the word
        address target = deploy(hex"604051505960005260206000f3");
        (bool ok, uint256 size) = callWord(target, "");
        assert(ok);
        assertEq(size, 0x60);
    }

    function check_msize_after_keccak256() public {
        // KECCAK256(offset: 0x40, size: 32) POP MSIZE; return the word
        address target = deploy(hex"6020604020505960005260206000f3");
        (bool ok, uint256 size) = callWord(target, "");
        assert(ok);
        assertEq(size, 0x60);
    }

    function check_msize_after_call_output() public {
        // STATICCALL(gas, identity, in: [0, 0), out: [0x80, 0xa0)) POP MSIZE; return the word
        // the identity precompile returns nothing, but the output region is still expanded
        address target = deploy(hex"602060806000600060045afa505960005260206000f3");
        (bool ok, uint256 size) = callWord(target, "");
        assert(ok);
        assertEq(size, 0xa0);
    }
}
