// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {ECDSA} from "openzeppelin/utils/cryptography/ECDSA.sol";

/// DO NOT USE, this demonstrates signature malleability problems
contract BadElections {
    event Voted(uint256 proposalId, bool support, address voter);

    mapping (bytes32 => bool) hasVoted;

    // maps proposalId to vote count
    mapping (uint256 => uint256) public votesFor;
    mapping (uint256 => uint256) public votesAgainst;

    // https://eips.ethereum.org/EIPS/eip-2098
    // available in older OZ versions:
    // https://github.com/OpenZeppelin/openzeppelin-contracts/blob/v4.7.0/contracts/utils/cryptography/ECDSA.sol#L57
    function recoverCompactSignature(bytes32 hash, bytes memory signature) internal pure returns (address) {
        if (signature.length == 64) {
            bytes32 r;
            bytes32 vs;
            // ecrecover takes the signature parameters, and the only way to get them
            // currently is to use assembly.
            /// @solidity memory-safe-assembly
            assembly {
                r := mload(add(signature, 0x20))
                vs := mload(add(signature, 0x40))
            }
            return ECDSA.recover(hash, r, vs);
        } else {
            return address(0);
        }
    }

    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        if (signature.length == 64) {
            return recoverCompactSignature(hash, signature);
        } else {
            return ECDSA.recover(hash, signature);
        }
    }

    // vote on a proposal by signature, anyone can cast a vote on behalf of someone else
    function vote(uint256 proposalId, bool support, address voter, bytes calldata signature) public {
        bytes32 sigHash = keccak256(signature);
        require(!hasVoted[sigHash], "already voted");

        bytes32 badSigDigest = keccak256(abi.encode(proposalId, support, voter));
        address recovered = recover(badSigDigest, signature);
        require(recovered == voter, "invalid signature");
        require(recovered != address(0), "invalid signature");

        // prevent replay
        hasVoted[sigHash] = true;

        // record vote
        if (support) {
            votesFor[proposalId]++;
        } else {
            votesAgainst[proposalId]++;
        }

        emit Voted(proposalId, support, voter);
    }
}
