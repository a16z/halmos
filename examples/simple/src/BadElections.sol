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

    // vote on a proposal by signature, anyone can cast a vote on behalf of someone else
    function vote(uint256 proposalId, bool support, address voter, bytes calldata signature) public {
        bytes32 sigHash = keccak256(signature);
        require(!hasVoted[sigHash], "already voted");

        bytes32 badSigDigest = keccak256(abi.encode(proposalId, support, voter));
        address recovered = ECDSA.recover(badSigDigest, signature);
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
