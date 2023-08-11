// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Test} from "forge-std/Test.sol";

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
}
