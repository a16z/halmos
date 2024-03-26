// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

import {SymTest} from "halmos-cheatcodes/SymTest.sol";

import {BadElections} from "src/BadElections.sol";

contract BadElectionsTest is SymTest, Test {
    BadElections elections;

    function setUp() public {
        elections = new BadElections();
    }

    /// The output will look something like this:
    ///
    ///     Running 1 tests for test/BadElections.t.sol:BadElectionsTest
    ///     Counterexample:
    ///         halmos_fakeSig_bytes_01 = 0x00000000000000000000000000000000000000000000000000000000000000003fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a100 (65 bytes)
    ///         p_proposalId_uint256 = 0x0000000000000000000000000000000000000000000000000000000000000000 (0)
    ///     [FAIL] check_canNotVoteTwice(uint256) (paths: 7, time: 0.63s, bounds: [])
    ///
    /// the counterexample values are not meaningful, but examining the trace shows
    /// that halmos found a signature s.t. the voter can vote twice on the same proposal,
    /// and the final vote count is 2
    function check_canNotVoteTwice(uint256 proposalId) public {
        // setup
        bool support = true;
        (address voter, uint256 privateKey) = makeAddrAndKey("voter");

        bytes32 sigDigest = keccak256(abi.encode(proposalId, support, voter));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(privateKey, sigDigest);
        bytes memory signature = abi.encodePacked(r, s, v);

        // we start with no vote
        assertEq(elections.votesFor(proposalId), 0);

        // when we cast the vote
        elections.vote(proposalId, support, voter, signature);

        // then the vote count increases
        assertEq(elections.votesFor(proposalId), 1);

        // when we vote again with the same signature, it reverts
        try elections.vote(proposalId, support, voter, signature) {
            assert(false);
        } catch {
            // expected
        }

        // when the same voter votes with a different signature
        elections.vote(proposalId, support, voter, svm.createBytes(65, "fakeSig"));

        // then the vote count remains unchanged
        // @note spoiler alert: it does not
        assertEq(elections.votesFor(proposalId), 1);
    }
}
