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
    uint256 MEGA_SIZE = 10 ** 32;

    function setUp() public {
        // blank
    }

    /// HELPERS

    function _call(uint256 in_ptr, uint256 in_len, uint256 out_ptr, uint256 out_len) internal {
        address addr = address(this);
        uint256 value = 0;
        bool success;
        assembly {
            success := call(gas(), addr, value, in_ptr, in_len, out_ptr, out_len)
        }
    }

    function _keccak256(uint256 ptr, uint256 len) internal pure {
        assembly {
            let hash := keccak256(ptr, len)
        }
    }

    function _mcopy(uint256 dst_ptr, uint256 src_ptr, uint256 src_len) internal pure {
        assembly {
            mcopy(dst_ptr, src_ptr, src_len)
        }
    }

    function _return(uint256 ptr, uint256 len) internal pure {
        assembly {
            return(ptr, len)
        }
    }

    function _revert(uint256 ptr, uint256 len) internal pure {
        assembly {
            revert(ptr, len)
        }
    }

    function _log0(uint256 ptr, uint256 len) internal {
        assembly {
            log0(ptr, len)
        }
    }

    function _returndatacopy(uint256 dst_ptr, uint256 src_ptr, uint256 src_len) internal pure {
        assembly {
            returndatacopy(dst_ptr, src_ptr, src_len)
        }
    }

    function _calldatacopy(uint256 dst_ptr, uint256 src_ptr, uint256 src_len) internal pure {
        assembly {
            calldatacopy(dst_ptr, src_ptr, src_len)
        }
    }

    function _codecopy(uint256 dst_ptr, uint256 src_ptr, uint256 src_len) internal pure {
        assembly {
            codecopy(dst_ptr, src_ptr, src_len)
        }
    }

    function _extcodecopy(uint256 dst_ptr, uint256 src_ptr, uint256 src_len) internal view {
        assembly {
            extcodecopy(address(), dst_ptr, src_ptr, src_len)
        }
    }

    function _create(uint256 src_ptr, uint256 src_len) internal {
        uint256 value = 0;
        assembly {
            let addr := create(value, src_ptr, src_len)
        }
    }

    function _create2(uint256 src_ptr, uint256 src_len) internal {
        uint256 value = 0;
        uint256 salt = 0;
        assembly {
            let addr := create2(value, src_ptr, src_len, salt)
        }
    }

    /// @dev just return some data, so that returndatacopy can be tested
    function dummy() public pure returns(uint256) {
        return 42;
    }

    /// @dev public wrapper for revert, so that we can call it and check the return value
    function just_revert(uint256 ptr, uint256 len) public pure {
        _revert(ptr, len);
    }

    /// TESTS

    function check_megaMem_new_bytes(bool coinflip) external view returns (bytes memory) {
        return new bytes(coinflip ? MEGA_SIZE : 32);
    }

    function check_megaMem_keccak256_ptr(bool coinflip) external view {
        _keccak256({ptr: coinflip ? MEGA_SIZE : 0, len: 32});
    }

    function check_megaMem_keccak256_len(bool coinflip) external view {
        _keccak256({ptr: 0, len: coinflip ? MEGA_SIZE : 32});
    }

    function check_megaMem_call_in_ptr(bool coinflip) external {
        _call({in_ptr: coinflip ? MEGA_SIZE : 0, in_len: 32, out_ptr: 0, out_len: 32});
    }

    function check_megaMem_call_in_len(bool coinflip) external {
        _call({in_ptr: 0, in_len: coinflip ? MEGA_SIZE : 32, out_ptr: 0, out_len: 32});
    }

    function check_megaMem_call_out_ptr(bool coinflip) external {
        _call({in_ptr: 0, in_len: 32, out_ptr: coinflip ? MEGA_SIZE : 0, out_len: 32});
    }

    function check_megaMem_call_out_len(bool coinflip) external {
        _call({in_ptr: 0, in_len: 32, out_ptr: 0, out_len: coinflip ? MEGA_SIZE : 32});
    }

    function check_megaMem_mcopy_dst_ptr(bool coinflip) external view {
        _mcopy({dst_ptr: coinflip ? MEGA_SIZE : 0, src_ptr: 0, src_len: 1});
    }

    function check_megaMem_mcopy_src_ptr(bool coinflip) external view {
        _mcopy({dst_ptr: 0, src_ptr: coinflip ? MEGA_SIZE : 0, src_len: 1});
    }

    function check_megaMem_mcopy_src_len(bool coinflip) external view {
        _mcopy({dst_ptr: 0, src_ptr: 0, src_len: coinflip ? MEGA_SIZE : 1});
    }

    function check_megaMem_return_ptr(bool coinflip) external view returns (bytes memory) {
        _return({ptr: coinflip ? MEGA_SIZE : 0, len: 32});
    }

    function check_megaMem_return_len(bool coinflip) external view returns (bytes memory) {
        _return({ptr: 0, len: coinflip ? MEGA_SIZE : 32});
    }

    function check_megaMem_log0_ptr(bool coinflip) external {
        _log0({ptr: coinflip ? MEGA_SIZE : 0, len: 32});
    }

    function check_megaMem_log0_len(bool coinflip) external {
        _log0({ptr: 0, len: coinflip ? MEGA_SIZE : 32});
    }

    function check_megaMem_mstore(bool coinflip) external view {
        uint256 loc = coinflip ? MEGA_SIZE : 0;
        assembly {
            mstore(loc, 42)
        }
    }

    function check_megaMem_mstore8(bool coinflip) external view {
        uint256 loc = coinflip ? MEGA_SIZE : 0;
        assembly {
            mstore8(loc, 42)
        }
    }

    function check_megaMem_mload(bool coinflip) external view {
        uint256 loc = coinflip ? MEGA_SIZE : 0;
        assembly {
            let x := mload(loc)
        }
    }

    function check_megaMem_returndatacopy_dst_ptr(bool coinflip) external view {
        MegaMemTest(address(this)).dummy();
        _returndatacopy({dst_ptr: coinflip ? MEGA_SIZE : 0, src_ptr: 0, src_len: 32});
    }

    function check_megaMem_returndatacopy_src_ptr(bool coinflip) external view {
        MegaMemTest(address(this)).dummy();
        _returndatacopy({dst_ptr: 0, src_ptr: coinflip ? MEGA_SIZE : 0, src_len: 32});
    }

    function check_megaMem_returndatacopy_src_len(bool coinflip) external view {
        MegaMemTest(address(this)).dummy();
        _returndatacopy({dst_ptr: 0, src_ptr: 0, src_len: coinflip ? MEGA_SIZE : 32});
    }

    function check_megaMem_revert_ptr(bool coinflip) external view {
        try this.just_revert({ptr: coinflip ? MEGA_SIZE : 0, len: 32}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_revert_len(bool coinflip) external view {
        try this.just_revert({ptr: 0, len: coinflip ? MEGA_SIZE : 32}) {
            assert(false);
        } catch {
            // success
        }
    }

    function check_megaMem_calldatacopy_dst_ptr(bool coinflip) external view {
        _calldatacopy({dst_ptr: coinflip ? MEGA_SIZE : 0, src_ptr: 0, src_len: 32});
    }

    function check_megaMem_calldatacopy_src_ptr(bool coinflip) external view {
        _calldatacopy({dst_ptr: 0, src_ptr: coinflip ? MEGA_SIZE : 0, src_len: 32});
    }

    function check_megaMem_calldatacopy_src_len(bool coinflip) external view {
        _calldatacopy({dst_ptr: 0, src_ptr: 0, src_len: coinflip ? MEGA_SIZE : 32});
    }

    function check_megaMem_calldataload(bool coinflip) external view {
        uint256 loc = coinflip ? MEGA_SIZE : 0;
        assembly {
            let x := calldataload(loc)
        }
    }

    function check_megaMem_codecopy_dst_ptr(bool coinflip) external view {
        _codecopy({dst_ptr: coinflip ? MEGA_SIZE : 0, src_ptr: 0, src_len: 32});
    }

    function check_megaMem_codecopy_src_ptr(bool coinflip) external view {
        _codecopy({dst_ptr: 0, src_ptr: coinflip ? MEGA_SIZE : 0, src_len: 32});
    }

    function check_megaMem_codecopy_src_len(bool coinflip) external view {
        _codecopy({dst_ptr: 0, src_ptr: 0, src_len: coinflip ? MEGA_SIZE : 32});
    }

    function check_megaMem_extcodecopy_dst_ptr(bool coinflip) external view {
        _extcodecopy({dst_ptr: coinflip ? MEGA_SIZE : 0, src_ptr: 0, src_len: 32});
    }

    function check_megaMem_extcodecopy_src_ptr(bool coinflip) external view {
        _extcodecopy({dst_ptr: 0, src_ptr: coinflip ? MEGA_SIZE : 0, src_len: 32});
    }

    function check_megaMem_extcodecopy_src_len(bool coinflip) external view {
        _extcodecopy({dst_ptr: 0, src_ptr: 0, src_len: coinflip ? MEGA_SIZE : 32});
    }

    function check_megaMem_create_src_ptr(bool coinflip) external {
        _create({src_ptr: coinflip ? MEGA_SIZE : 0, src_len: 32});
    }

    function check_megaMem_create_src_len(bool coinflip) external {
        _create({src_ptr: 0, src_len: coinflip ? MEGA_SIZE : 32});
    }

    function check_megaMem_create2_src_ptr(bool coinflip) external {
        _create2({src_ptr: coinflip ? MEGA_SIZE : 0, src_len: 32});
    }

    function check_megaMem_create2_src_len(bool coinflip) external {
        _create2({src_ptr: 0, src_len: coinflip ? MEGA_SIZE : 32});
    }
}
