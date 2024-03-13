// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

import {SignatureChecker} from "openzeppelin/utils/cryptography/SignatureChecker.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

contract SymAccount is SymTest {
    fallback(bytes calldata) external payable returns (bytes memory) {
        uint mode = svm.createUint256("mode");
        if (mode == 0) {
            return ""; // simulate empty code
        } else if (mode == 1) {
            return svm.createBytes(32, "retdata32"); // any primitive return value: bool, address, uintN, bytesN, etc
        } else if (mode == 2) {
            return svm.createBytes(64, "retdata64"); // two primitive return values
        } else {
            revert(); // simulate no fallback
        }
    }
}

contract SignatureTest is SymTest, Test {
    uint256 constant private ECRECOVER_PRECOMPILE = 1;

    function check_isValidSignatureNow(bytes32 hash, bytes memory signature) public {
        address signer = address(new SymAccount());
        if (!SignatureChecker.isValidSignatureNow(signer, hash, signature)) revert();
        assert(true);
    }

    function check_isValidERC1271SignatureNow(bytes32 hash, bytes memory signature) public {
        address signer = address(new SymAccount());
        if (!SignatureChecker.isValidERC1271SignatureNow(signer, hash, signature)) revert();
        assert(true);
    }

    function check_tryRecover(address signer, bytes32 hash, bytes memory signature) public {
        (address recovered, ECDSA.RecoverError error, ) = ECDSA.tryRecover(hash, signature);
        if (!(error == ECDSA.RecoverError.NoError && recovered == signer)) revert();
        assert(true);
    }

    function check_ecrecover(
        bytes32 hash,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public {
        address signer = ecrecover(hash, v, r, s);
        if (signer == address(0)) revert();
        assert(true);
    }

    function check_vmaddr_consistent(uint256 privateKey) public {
        address addr1 = vm.addr(privateKey);
        address addr2 = vm.addr(privateKey);

        assertEq(addr1, addr2);
    }

    function check_vmaddr_noCollision_symbolic(
        uint256 privateKey1,
        uint256 privateKey2
    ) public {
        vm.assume(privateKey1 != privateKey2);

        address addr1 = vm.addr(privateKey1);
        address addr2 = vm.addr(privateKey2);

        assertNotEq(addr1, addr2);
    }

    function check_vmaddr_noCollision_concrete(
        uint256 privateKey1,
        uint256 privateKey2
    ) public {
        assertNotEq(vm.addr(42), vm.addr(43));
    }

    /// FIXME: this returns a counterexample, but it shouldn't
    // function check_vmaddr_concreteKey() public {
    //     address addr = vm.addr(0x42);
    //     assertEq(0x6f4c950442e1Af093BcfF730381E63Ae9171b87a);
    // }

    /// FIXME: this returns a counterexample, but it shouldn't
    // function check_vmaddr_saneAddressConstraints(uint256 privateKey) public {
    //     address addr = vm.addr(privateKey);
    //     assertNotEq(addr, address(0));
    //     assertNotEq(addr, address(this));
    // }

    /// we expect a counterexample for this test
    /// the addresses match if the private keys are equal
    function check_vmaddr_canFindKeyForAddr_symbolic(
        uint256 privateKey1,
        uint256 privateKey2
    ) public {
        address addr1 = vm.addr(privateKey1);
        address addr2 = vm.addr(privateKey2);

        assertNotEq(addr1, addr2);
    }

    /// we expect a counterexample for this test
    /// the addresses match if the private keys are equal
    function check_vmaddr_canFindKeyForAddr_mixed(
        uint256 privateKey
    ) public {
        address addr1 = vm.addr(0x42);
        address addr2 = vm.addr(privateKey);

        assertNotEq(addr1, addr2);
    }

    /// we expect a counterexample (the key for a given address which is ofc nonsense)
    /// that's because we only add constraints about the relations between
    /// different vm.addr() calls, but not about specific addresses
    function check_vmaddr_canFindKeyForAddr_concrete(uint256 privateKey) public {
        address addr = vm.addr(privateKey);
        assertNotEq(addr, address(0x42));
    }

    function check_vmsign_consistent(
        uint256 privateKey,
        bytes32 digest
    ) public {
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(privateKey, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(privateKey, digest);

        assertEq(v1, v2);
        assertEq(r1, r2);
        assertEq(s1, s2);
    }

    function check_vmsign_noDigestCollision(
        uint256 privateKey,
        bytes32 digest1,
        bytes32 digest2
    ) public {
        vm.assume(digest1 != digest2);

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(privateKey, digest1);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(privateKey, digest2);

        assertNotEq(r1, r2);
        assertNotEq(s1, s2);
    }

    function check_vmsign_noKeyCollision(
        uint256 privateKey1,
        uint256 privateKey2,
        bytes32 digest
    ) public {
        vm.assume(privateKey1 != privateKey2);

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(privateKey1, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(privateKey2, digest);

        assertNotEq(r1, r2);
        assertNotEq(s1, s2);
    }

    /// we expect a counterexample for this test
    /// the signatures match if the private keys are equal
    function check_vmsign_canFindKeyForGivenSig(
        uint256 privateKey1,
        uint256 privateKey2,
        bytes32 digest
    ) public {
        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(privateKey1, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(privateKey2, digest);

        assertNotEq(r1, r2);
    }
}
