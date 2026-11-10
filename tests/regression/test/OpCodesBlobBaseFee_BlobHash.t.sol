// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.24 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

// =============================================================================
// BLOBBASEFEE (0x4A) — EIP-4844 / Cancun
// =============================================================================

contract BlobBaseFeeTest is SymTest, Test {

    /// In foundry env test, blobbasefee == 0
    function check_blobbasefee_zero_in_test_env() public view {
        uint256 fee;
        assembly { fee := blobbasefee() }
        assertEq(fee, 0);
    }

    /// block.blobbasefee  == opcode 0x4A
    function check_blobbasefee_solidity_matches_opcode() public view {
        uint256 via_opcode;
        assembly { via_opcode := blobbasefee() }
        assertEq(via_opcode, block.blobbasefee);
    }

    // -------------------------------------------------------------------------
    // Formal properties
    // -------------------------------------------------------------------------

    function check_blobbasefee_no_revert() public view {
        uint256 fee;
        assembly { fee := blobbasefee() }
        assert(fee == fee);
    }

    function check_blobbasefee_affordable(uint256 maxFee) public view {
        uint256 fee;
        assembly { fee := blobbasefee() }
        if (fee <= maxFee) {
            assert(fee <= maxFee);
        }
    }
}

// =============================================================================
// BLOBHASH (0x49) — EIP-4844 / Cancun
// =============================================================================

contract BlobHashTest is SymTest, Test {

    // -------------------------------------------------------------------------
    // Cas concrets (pas de blob dans l'env de test → toujours 0)
    // -------------------------------------------------------------------------

    function check_blobhash_zero_no_blob_tx() public view {
        bytes32 h0;
        bytes32 h5;
        assembly {
            h0 := blobhash(0)
            h5 := blobhash(5)
        }
        assertEq(h0, bytes32(0));
        assertEq(h5, bytes32(0));
    }

    function check_blobhash_out_of_range() public view {
        bytes32 h;
        assembly { h := blobhash(6) }
        assertEq(h, bytes32(0));
    }

    // -------------------------------------------------------------------------
    // Formal properties
    // -------------------------------------------------------------------------

    function check_blobhash_version_byte(uint8 index) public view {
        if (index > 5) return;
        bytes32 h;
        uint256 idx = uint256(index);
        assembly { h := blobhash(idx) }
        if (h != bytes32(0)) {
            // Premier octet == 0x01 (KZG commitment version)
            uint8 version = uint8(uint256(h) >> 248);
            assert(version == 0x01);
        }
    }

    /// blobhash never revert
    function check_blobhash_no_revert(uint8 index) public view {
        bytes32 h;
        uint256 idx = uint256(index);
        assembly { h := blobhash(idx) }
        // reachable sans revert
        assert(h == h);
    }

    /// Deterministic
    function check_blobhash_deterministic(uint8 index) public view {
        if (index > 5) return;
        uint256 idx = uint256(index);
        bytes32 h1;
        bytes32 h2;
        assembly {
            h1 := blobhash(idx)
            h2 := blobhash(idx)
        }
        assert(h1 == h2);
    }

    function check_blobhash_contiguous(uint8 index) public view {
        if (index >= 5) return;
        uint256 idx = uint256(index);
        bytes32 hi;
        bytes32 hi1;
        assembly {
            hi  := blobhash(idx)
            hi1 := blobhash(add(idx, 1))
        }
        if (hi == bytes32(0)) {
            assert(hi1 == bytes32(0));
        }
    }
}
