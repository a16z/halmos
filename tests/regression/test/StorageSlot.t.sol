// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract StorageSlotTest {
    mapping (uint => uint) map;

    // keccak256(abi.encode(1, 0))
    bytes32 constant slot_map_one = bytes32(0xada5013122d395ba3c54772283fb069b10426056ef8ca54750cb9bb552a59e7d);

    // keccak256(abi.encode(2, 0))
    bytes32 constant slot_map_two = bytes32(0xabbb5caa7dda850e60932de0934eb1f9d0f59695050f761dc64e443e5030a569);

    // not annotated as constant to avoid constant propagation optimization
    uint one = 1;
    uint two = 2;

    function check_setup() public {
        assert(slot_map_one == keccak256(abi.encode(1, 0)));
    }

    function check_keccak_slot_1_pass(uint value) public {
        // note: compiler doesn't optimize because global variable is used as key
        map[one] = value; // sstore with keccak expression

        assert(sload(slot_map_one) == value); // sload with precomputed hash
        assert(map[one] == value); // sload with keccak expression
    }

    // this test passes because halmos internally precomputes the slots for m[0] and m[1], for any m where slot(m) < 256.
    // in general, however, directly initializing storage with a precomputed hash is not supported by halmos. see the test below.
    function check_keccak_slot_2_pass(uint value) public {
        sstore(slot_map_one, value); // sstore with precomputed hash

        assert(sload(slot_map_one) == value); // sload with precomputed hash
        assert(map[one] == value); // sload with keccak expression
    }

    // this test failed due to m[2] beyond the scope of halmos internal precomputation. see the above test for comparison.
    function check_keccak_slot_2_fail(uint value) public {
        sstore(slot_map_two, value); // sstore with precomputed hash

        assert(sload(slot_map_two) == value); // sload with precomputed hash
        assert(map[two] == value); // sload with keccak expression
    }

    function check_keccak_slot_3_pass(uint value) public {
        // note: compiler may or may not optimize depending on compiler version or other optimization configuration
        map[1] = value; // may be optimized to sstore with precomputed hash

        assert(sload(slot_map_one) == value); // sload with precomputed hash
        assert(map[one] == value); // sload with keccak expression
    }

    function sload(bytes32 slot) internal returns (uint value) {
        assembly {
            value := sload(slot)
        }
    }

    function sstore(bytes32 slot, uint value) internal {
        assembly {
            sstore(slot, value)
        }
    }
}
