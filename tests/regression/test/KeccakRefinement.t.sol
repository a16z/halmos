// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

// a16z/halmos#562: keccak256 is uninterpreted, so the solver may assign to a symbolic
// preimage a hash value that differs from the real one. Such counterexamples are checked
// against the real keccak256 values, and reported as potentially invalid if they do not agree.
//
// The solidity storage layout is required: the generic layout decodes hashed storage keys
// structurally, so a hash can never be equal to the plain key written in setUp, and the
// counterexample path is pruned during exploration.
/// @custom:dolmos --storage-layout solidity
contract KeccakRefinementTest {
    mapping(uint256 => uint256) balances;

    // not a constant, to prevent the optimizer from folding the slot computation
    uint256 key = 0xfaaaaaffafafafafaaaaa472134;

    function setUp() public {
        balances[key] = 50;
    }

    // the only counterexamples need a preimage of `key`, which is not known:
    // the counterexample must not be reported as valid
    function check_keccak_unknown_preimage(uint256 amt) public view {
        bytes32 hash = keccak256(abi.encodePacked(amt));
        uint256 balance = balances[uint256(hash)];
        assert(balance != 50);
    }

    // a genuine counterexample involving keccak256 is still reported as valid: amt == 42
    function check_keccak_known_preimage(uint256 amt) public pure {
        bytes32 hash = keccak256(abi.encodePacked(amt));
        assert(hash != keccak256(abi.encodePacked(uint256(42))));
    }

    // properties that hold are not affected
    function check_keccak_injective(uint256 a, uint256 b) public pure {
        if (a != b) {
            assert(keccak256(abi.encodePacked(a)) != keccak256(abi.encodePacked(b)));
        }
    }
}
