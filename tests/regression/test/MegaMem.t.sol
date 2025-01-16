// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

import {SymTest} from "halmos-cheatcodes/SymTest.sol";

/// @dev This checks that halmos can handle large memory operations without raising
/// internal errors like "cannot fit 'int' into an index-sized integer".
/// Instead, we should catch the error and revert the current path, but letting other
/// paths continue. This is why these tests do a symbolic coinflip, we case split:
/// - a normal, non-problematic path
/// - a problematic path with large memory indices or sizes
/// and we just check that the problematic path does not lead to a failed test
contract MegaMemTest is Test, SymTest {
    uint256 BIG = 10 ** 32;
    uint256 BIG_PTR = BIG;
    uint256 BIG_LEN = BIG;

    function setUp() public {
        // blank
    }

    /// HELPERS

    modifier writes_to_memory(uint256 ptr, uint256 val) {
        // setup: write a cookie to memory and verify it
        uint256 cookie = type(uint256).max;
        mstore(ptr, cookie);
        assertEq(mload(ptr), cookie);

        _;

        assertEq(mload(ptr), val);
    }

    /// @dev makes sure that
    modifier has_return_data(uint256 ptr, uint256 val) {
        // setup: write a cookie to memory and verify it
        uint256 cookie = type(uint256).max;
        mstore(0, cookie);
        assertEq(mload(0), cookie);

        // make a call that populates returndata[0:32] with `val`
        this.dummy(val);

        // verify that we can copy the return data and read the expected value
        returndatacopy(ptr, 0, 32);
        assertEq(mload(ptr), val);

        _;
    }

    /// @dev just return some data, so that returndatacopy can be tested
    function dummy(uint256 val) public pure returns (uint256) {
        return val;
    }

    fallback(bytes calldata) external returns (bytes memory) {
        // just here to make sure we can call this contract with the null selector
        // without reverting (and with some actual return data)
        return new bytes(32);
    }

    function new_bytes(uint256 len) public pure returns (bytes memory) {
        return new bytes(len);
    }

    function call_op(uint256 in_ptr, uint256 in_len, uint256 out_ptr, uint256 out_len) public {
        address addr = address(this);
        uint256 value = 0;
        bool success;
        assembly {
            success := call(gas(), addr, value, in_ptr, in_len, out_ptr, out_len)
        }
    }


    function keccak256_op(uint256 ptr, uint256 len) public pure returns (bytes32) {
        bytes32 hash;
        assembly {
            hash := keccak256(ptr, len)
        }
        return hash;
    }

    function mcopy(uint256 dst_ptr, uint256 src_ptr, uint256 src_len) public pure {
        assembly {
            mcopy(dst_ptr, src_ptr, src_len)
        }
    }

    function return_op(uint256 ptr, uint256 len) public pure {
        assembly {
            return(ptr, len)
        }
    }

    function revert_op(uint256 ptr, uint256 len) public pure {
        assembly {
            revert(ptr, len)
        }
    }

    function log0(uint256 ptr, uint256 len) public {
        assembly {
            log0(ptr, len)
        }
    }

    function returndatacopy(uint256 dst_ptr, uint256 src_ptr, uint256 src_len) public pure {
        assembly {
            returndatacopy(dst_ptr, src_ptr, src_len)
        }
    }

    function calldatacopy(uint256 dst_ptr, uint256 src_ptr, uint256 src_len) public pure {
        assembly {
            calldatacopy(dst_ptr, src_ptr, src_len)
        }
    }

    function calldataload(uint256 src_ptr) public pure returns (uint256) {
        uint256 val;
        assembly {
            val := calldataload(src_ptr)
        }
        return val;
    }

    function codecopy(uint256 dst_ptr, uint256 src_ptr, uint256 src_len) public pure {
        assembly {
            codecopy(dst_ptr, src_ptr, src_len)
        }
    }

    function extcodecopy(uint256 dst_ptr, uint256 src_ptr, uint256 src_len) public view {
        assembly {
            extcodecopy(address(), dst_ptr, src_ptr, src_len)
        }
    }

    function create(uint256 src_ptr, uint256 src_len) public {
        uint256 value = 0;
        assembly {
            let addr := create(value, src_ptr, src_len)
        }
    }

    function create2(uint256 src_ptr, uint256 src_len) public {
        uint256 value = 0;
        uint256 salt = 0;
        assembly {
            let addr := create2(value, src_ptr, src_len, salt)
        }
    }

    function mload(uint256 src_ptr) public view returns (uint256) {
        uint256 x;
        assembly {
            x := mload(src_ptr)
        }
        return x;
    }

    function mstore(uint256 dst_ptr, uint256 val) public pure {
        assembly {
            mstore(dst_ptr, val)
        }
    }

    function mstore8(uint256 dst_ptr, uint256 val) public pure {
        assembly {
            mstore8(dst_ptr, val)
        }
    }

    /// TESTS

    function check_megaMem_new_bytes_reverts() external view {
        try this.new_bytes(BIG_LEN) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_keccak256_ptr_reverts(bool coinflip) external view {
        uint256 src_len = coinflip ? 0 : 1;

        try this.keccak256_op(BIG_PTR, src_len) {
            // ok if src_len == 0
            assertEq(src_len, 0);
        } catch {
            // reverts if src_len > 0
            assertGt(src_len, 0);
        }
    }

    function check_megaMem_keccak256_len_reverts() external view {
        try this.keccak256_op(0, BIG_LEN) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_call_in_ptr_reverts(bool coinflip) external {
        uint256 in_len = coinflip ? 1 : 0;

        try this.call_op({in_ptr: BIG_PTR, in_len: in_len, out_ptr: 0, out_len: 32}) {
            // ok if in_len == 0
            assertEq(in_len, 0);
        } catch {
            // reverts if in_len > 0
            assertGt(in_len, 0);
        }
    }

    function check_megaMem_call_in_len_reverts() external {
        try this.call_op({in_ptr: 0, in_len: BIG_LEN, out_ptr: 0, out_len: 32}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_call_out_ptr_reverts(bool coinflip) external {
        uint256 out_len = coinflip ? 1 : 0;

        try this.call_op({in_ptr: 0, in_len: 32, out_ptr: BIG_PTR, out_len: out_len}) {
            // ok if out_len == 0
            assertEq(out_len, 0);
        } catch {
            // reverts if out_len > 0
            assertGt(out_len, 0);
        }
    }

    /// @dev only the effective length is copied, not a big requested length
    function check_megaMem_call_out_len_ok() external {
        call_op({in_ptr: 0, in_len: 32, out_ptr: 0, out_len: BIG_LEN});
    }

    function check_megaMem_mcopy_dst_ptr_reverts() external view {
        try this.mcopy({dst_ptr: BIG_PTR, src_ptr: 0, src_len: 1}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_mcopy_src_ptr_reverts() external view {
        try this.mcopy({dst_ptr: 0, src_ptr: BIG_PTR, src_len: 1}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_mcopy_src_len_reverts() external view {
        try this.mcopy({dst_ptr: 0, src_ptr: 0, src_len: BIG_LEN}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_return_ptr_reverts() external view {
        try this.return_op({ptr: BIG_PTR, len: 32}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_return_len_reverts() external view {
        try this.return_op({ptr: 0, len: BIG_LEN}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_log0_ptr_reverts() external {
        try this.log0({ptr: BIG_PTR, len: 32}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_log0_len_reverts() external {
        try this.log0({ptr: 0, len: BIG_LEN}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_mstore_dst_ptr_reverts() external view {
        try this.mstore({dst_ptr: BIG_PTR, val: 42}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_mstore8_dst_ptr_reverts() external view {
        try this.mstore8({dst_ptr: BIG_PTR, val: 42}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_mload_src_ptr_reverts() external view {
        try this.mload(BIG_PTR) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_returndatacopy_dst_ptr_reverts(bool coinflip) external view has_return_data(0, 42) {
        uint256 src_len = coinflip ? 0 : 1;

        try this.returndatacopy({dst_ptr: BIG_PTR, src_ptr: 0, src_len: src_len}) {
            // ok if src_len == 0
            assertEq(src_len, 0);
        } catch {
            // reverts if src_len > 0
            assertGt(src_len, 0);
        }
    }

    function check_megaMem_returndatacopy_src_ptr_reverts() external view has_return_data(0, 42) {
        try this.returndatacopy({dst_ptr: 0, src_ptr: BIG_PTR, src_len: 32}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_returndatacopy_src_len_reverts() external view has_return_data(0, 42) {
        try this.returndatacopy({dst_ptr: 0, src_ptr: 0, src_len: BIG_LEN}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_revert_ptr_reverts() external view {
        try this.revert_op({ptr: BIG_PTR, len: 32}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_revert_len_reverts() external view {
        try this.revert_op({ptr: 0, len: BIG_LEN}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_calldatacopy_dst_ptr_reverts(bool coinflip) external view {
        uint256 src_len = coinflip ? 0 : 1;

        try this.calldatacopy({dst_ptr: BIG_PTR, src_ptr: 0, src_len: src_len}) {
            // ok if src_len == 0
            assertEq(src_len, 0);
        } catch {
            // reverts if src_len > 0
            assertGt(src_len, 0);
        }
    }

    function check_megaMem_calldatacopy_src_len_reverts() external view {
        try this.calldatacopy({dst_ptr: 0, src_ptr: 0, src_len: BIG_LEN}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_calldatacopy_src_ptr_ok() external view writes_to_memory(0, 0) {
        calldatacopy({dst_ptr: 0, src_ptr: BIG_PTR, src_len: 32});
    }

    function check_megaMem_calldataload_ok() external view {
        assertEq(calldataload(BIG_PTR), 0);
    }

    function check_megaMem_codecopy_dst_ptr_reverts(bool coinflip) external view {
        uint256 src_len = coinflip ? 0 : 1;

        try this.codecopy({dst_ptr: BIG_PTR, src_ptr: 0, src_len: src_len}) {
            // ok if src_len == 0
            assertEq(src_len, 0);
        } catch {
            // reverts if src_len > 0
            assertGt(src_len, 0);
        }
    }

    function check_megaMem_codecopy_src_len_reverts() external view {
        try this.codecopy({dst_ptr: 0, src_ptr: 0, src_len: BIG_LEN}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_codecopy_src_ptr_ok() external view writes_to_memory(0, 0) {
        codecopy({dst_ptr: 0, src_ptr: BIG_PTR, src_len: 32});
    }

    function check_megaMem_extcodecopy_dst_ptr_reverts(bool coinflip) external view {
        uint256 src_len = coinflip ? 0 : 1;

        try this.extcodecopy({dst_ptr: BIG_PTR, src_ptr: 0, src_len: src_len}) {
            // ok if src_len == 0
            assertEq(src_len, 0);
        } catch {
            // reverts if src_len > 0
            assertGt(src_len, 0);
        }
    }

    function check_megaMem_extcodecopy_src_len_reverts() external view {
        try this.extcodecopy({dst_ptr: 0, src_ptr: 0, src_len: BIG_LEN}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_extcodecopy_src_ptr_ok() external view writes_to_memory(0, 0) {
        extcodecopy({dst_ptr: 0, src_ptr: BIG_PTR, src_len: 32});
    }

    function check_megaMem_create_src_ptr_reverts() external {
        try this.create({src_ptr: BIG_PTR, src_len: 32}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_create_src_len_reverts() external {
        try this.create({src_ptr: 0, src_len: BIG_LEN}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_create2_src_ptr_reverts() external {
        try this.create2({src_ptr: BIG_PTR, src_len: 32}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_create2_src_len_reverts() external {
        try this.create2({src_ptr: 0, src_len: BIG_LEN}) {
            assert(false);
        } catch {
            // success
        }
    }
}
