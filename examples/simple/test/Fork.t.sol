// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract Counter {
    uint public total; // slot 0

    mapping (address => uint) public map; // slot 1

    function increment(address user) public {
        map[user]++;
        total++;
    }
}

contract EmptyContract { }

contract CounterForkTest is Test {
    Counter counter;

    // slot numbers found in "storageLayout" of Counter.json
    uint counter_total_slot = 0;
    uint counter_map_slot = 1;

    function setUp() public {
        // create a new (empty) contract
        counter = Counter(address(new EmptyContract()));

        // set the bytecode of `counter` to the given code
        vm.etch(address(counter), hex"608060405234801561000f575f80fd5b506004361061003f575f3560e01c80632ddbd13a1461004357806345f43dd81461005d578063b721ef6e14610072575b5f80fd5b61004b5f5481565b60405190815260200160405180910390f35b61007061006b3660046100cf565b610091565b005b61004b6100803660046100cf565b60016020525f908152604090205481565b6001600160a01b0381165f9081526001602052604081208054916100b4836100fc565b90915550505f805490806100c7836100fc565b919050555050565b5f602082840312156100df575f80fd5b81356001600160a01b03811681146100f5575f80fd5b9392505050565b5f6001820161011957634e487b7160e01b5f52601160045260245ffd5b506001019056fea26469706673582212202ef0183898a1560805c26d8e270f79f0c451b549a3d09da92d110096d1deffec64736f6c63430008150033");

        // set the storage slots to the given values
        vm.store(address(counter), bytes32(counter_total_slot), bytes32(uint(12))); // counter.total = 12
        vm.store(address(counter), keccak256(abi.encode(address(0x1001), counter_map_slot)), bytes32(uint(7))); // counter.map[0x1001] = 7
        vm.store(address(counter), keccak256(abi.encode(address(0x1002), counter_map_slot)), bytes32(uint(5))); // counter.map[0x1002] = 5

        /* NOTE: do _not_ use the keccak256 hash images as the slot number, since keccak256 is interpreted differently during symbolic execution
        vm.store(address(counter), bytes32(0xf04c2c5f6f9b62a2b5225d778c263b65e9f9e981a3c2cee9583d90b6a62a361c), bytes32(uint(7))); // counter.map[0x1001] = 7
        vm.store(address(counter), bytes32(0x292339123265925891d3d1c06602cc560d8bb722fcb2db8d37c0fc7a3456fc09), bytes32(uint(5))); // counter.map[0x1002] = 5
        */
    }

    function check_setup() public {
        assertEq(counter.total(), 12);
        assertEq(counter.map(address(0x1001)), 7);
        assertEq(counter.map(address(0x1002)), 5);
        assertEq(counter.map(address(0x1003)), 0); // uninitialized storage slots default to a zero value
    }

    function check_invariant(address user) public {
        assertLe(counter.map(user), counter.total());
    }
}
