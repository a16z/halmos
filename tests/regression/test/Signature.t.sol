// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Test} from "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

import {SignatureChecker} from "openzeppelin/utils/cryptography/SignatureChecker.sol";
import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

uint256 constant secp256k1n = 115792089237316195423570985008687907852837564279074904382605163141518161494337;

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
    //     assertEq(addr, 0x6f4c950442e1Af093BcfF730381E63Ae9171b87a);
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

    function check_vmsign_valuesInExpectedRange(
        uint256 privateKey,
        bytes32 digest
    ) public {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        assert(v == 27 || v == 28);
        assertGt(uint256(r), 0);
        assertLt(uint256(r), secp256k1n);
        assertGt(uint256(s), 0);
        assertLt(uint256(s), secp256k1n);
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

        bytes memory sig1 = abi.encodePacked(v1, r1, s1);
        bytes memory sig2 = abi.encodePacked(v2, r2, s2);
        assertNotEq(keccak256(sig1), keccak256(sig2));
    }

    function check_vmsign_noKeyCollision(
        uint256 privateKey1,
        uint256 privateKey2,
        bytes32 digest
    ) public {
        vm.assume(privateKey1 != privateKey2);

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(privateKey1, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(privateKey2, digest);

        assert(v1 != v2 || r1 != r2 || s1 != s2);
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

    /// FIXME: this should pass, but it doesn't because we always return 32 bytes
    // function check_ecrecover_invalidCallReturnsNothing() public {
    //     uint256 returnDataSize;
    //     assembly {
    //         let succ := call(gas(), ECRECOVER_PRECOMPILE, 0, 0, 0, 0, 0)
    //         returnDataSize := returndatasize()
    //     }

    //     assertEq(returnDataSize, 0);
    // }

    function check_vmsign_ecrecover_e2e_recoveredMatches(
        uint256 privateKey,
        bytes32 digest
    ) public {
        address originalAddr = vm.addr(privateKey);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        address recoveredAddr = ecrecover(digest, v, r, s);
        assertEq(originalAddr, recoveredAddr);
    }

    function check_vmsign_ecrecover_e2e_recoveredCanNotMatchOtherAddr(
        uint256 privateKey,
        bytes32 digest,
        address otherAddr
    ) public {
        address originalAddr = vm.addr(privateKey);
        vm.assume(originalAddr != otherAddr);

        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        address recoveredAddr = ecrecover(digest, v, r, s);
        assertNotEq(otherAddr, recoveredAddr);
    }

    /// we expect a counterexample for this test
    function check_ecrecover_solveForMalleability(
        uint256 privateKey,
        bytes32 digest
    ) public {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        // create another symbolic signature
        uint8 otherV = uint8(svm.createUint256("otherV"));
        bytes32 otherR = svm.createBytes32("otherR");
        bytes32 otherS = svm.createBytes32("otherS");

        vm.assume(v != otherV || r != otherR || s != otherS);

        assertNotEq(ecrecover(digest, v, r, s), ecrecover(digest, otherV, otherR, otherS));
    }

    function check_vmsign_tryRecover(
        uint256 privateKey,
        bytes32 digest
    ) public {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);
        bytes memory sig = abi.encodePacked(r, s, v);
        address originalAddr = vm.addr(privateKey);

        // we don't want ecrecover to return address(0), it would indicate an error
        vm.assume(originalAddr != address(0));

        (address recovered, ECDSA.RecoverError error, ) = ECDSA.tryRecover(digest, sig);
        if (error == ECDSA.RecoverError.InvalidSignatureS) {
            // tryRecover rejects s values in the high half order
            assertGt(uint256(s), secp256k1n / 2);
        } else {
            assertEq(uint256(error), uint256(ECDSA.RecoverError.NoError));
            assertEq(recovered, originalAddr);
        }
    }

    function check_ecrecover_explicitMalleability(
        uint256 privateKey,
        bytes32 digest
    ) public {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        assertEq(
            ecrecover(digest, v, r, s),
            ecrecover(digest, v ^ 1, r, bytes32(secp256k1n - uint256(s)))
        );
    }

    function check_ecrecover_sameKeyDistinctDigestsUniqueRecovery(
        uint256 privateKey,
        bytes32 digest1,
        bytes32 digest2
    ) public {
        vm.assume(digest1 != digest2);

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(privateKey, digest1);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(privateKey, digest2);

        assertEq(ecrecover(digest1, v1, r1, s1), ecrecover(digest2, v2, r2, s2));
    }

    function check_ecrecover_sameKeyDistinctDigestsCorrectRecovery(
        uint256 privateKey,
        bytes32 digest1,
        bytes32 digest2
    ) public {
        vm.assume(digest1 != digest2);

        address originalAddr = vm.addr(privateKey);

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(privateKey, digest1);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(privateKey, digest2);

        address addr1 = ecrecover(digest1, v1, r1, s1);
        assertEq(addr1, originalAddr);

        address addr2 = ecrecover(digest2, v2, r2, s2);
        assertEq(addr2, originalAddr);
    }

    function check_ecrecover_distinctKeysSameDigestDistinctAddrs(
        uint256 privateKey1,
        uint256 privateKey2,
        bytes32 digest
    ) public {
        vm.assume(privateKey1 != privateKey2);

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(privateKey1, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(privateKey2, digest);

        address addr1 = ecrecover(digest, v1, r1, s1);
        address addr2 = ecrecover(digest, v2, r2, s2);

        assertNotEq(addr1, addr2);
    }

    function check_ecrecover_distinctKeysSameDigestCorrectRecovery(
        uint256 privateKey1,
        uint256 privateKey2,
        bytes32 digest
    ) public {
        vm.assume(privateKey1 != privateKey2);

        (uint8 v1, bytes32 r1, bytes32 s1) = vm.sign(privateKey1, digest);
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(privateKey2, digest);

        assertEq(ecrecover(digest, v1, r1, s1), vm.addr(privateKey1));
        assertEq(ecrecover(digest, v2, r2, s2), vm.addr(privateKey2));
    }

    function check_ecrecover_eip2098CompactSignatures(
        uint256 privateKey,
        bytes32 digest
    ) public {
        address addr = vm.addr(privateKey);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, digest);

        // assume s is in the lower half order
        vm.assume(uint256(s) < secp256k1n / 2);

        // convert to compact format
        uint8 yParity = v - 27;
        bytes32 vs = bytes32(((uint256(yParity) << 255) | uint256(s)));

        // check that the compact signature can be verified
        address recovered = ECDSA.recover(digest, r, vs);
        assertEq(recovered, addr);
    }

    function check_makeAddrAndKey_consistent_symbolic() public {
        string memory keyName = svm.createString(32, "keyName");
        (address addr, uint256 key) = makeAddrAndKey(keyName);

        assertEq(addr, vm.addr(key));
    }

    function check_makeAddrAndKey_consistent_concrete() public {
        (address addr, uint256 key) = makeAddrAndKey("someKey");

        assertEq(addr, vm.addr(key));
    }

    function check_makeAddrAndKey_noCollision_symbolic() public {
        string memory keyName1 = svm.createString(32, "keyName1");
        (address addr1, uint256 key1) = makeAddrAndKey(keyName1);

        string memory keyName2 = svm.createString(32, "keyName2");
        (address addr2, uint256 key2) = makeAddrAndKey(keyName2);

        // assume distinct keys
        vm.assume(keccak256(abi.encodePacked(keyName1)) != keccak256(abi.encodePacked(keyName2)));

        assertNotEq(key1, key2);
        assertNotEq(addr1, addr2);
        assertEq(vm.addr(key1), addr1);
        assertEq(vm.addr(key2), addr2);
    }

    function check_makeAddrAndKey_noCollision_concrete() public {
        (address addr1, uint256 key1) = makeAddrAndKey("someKey");
        (address addr2, uint256 key2) = makeAddrAndKey("anotherKey");

        assertNotEq(key1, key2);
        assertNotEq(addr1, addr2);
        assertEq(vm.addr(key1), addr1);
        assertEq(vm.addr(key2), addr2);
    }

    // TODO: remove the following option after fixing issue in case of empty keyName
    /// @custom:halmos --array-lengths keyName={65,1024}
    function check_makeAddrAndKey_vmsign_ecrecover_e2e_symbolic(
        string memory keyName,
        bytes32 digest
    ) public {
        (address addr, uint256 key) = makeAddrAndKey(keyName);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        address recoveredAddr = ecrecover(digest, v, r, s);
        assertEq(addr, recoveredAddr);
    }

    function check_makeAddrAndKey_vmsign_ecrecover_e2e_concrete() public {
        (address addr, uint256 key) = makeAddrAndKey("someKey");
        bytes32 digest = keccak256(abi.encodePacked("someData"));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        address recoveredAddr = ecrecover(digest, v, r, s);
        assertEq(addr, recoveredAddr);
    }
}
