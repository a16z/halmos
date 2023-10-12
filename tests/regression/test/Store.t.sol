// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract C {
    uint public x;
    mapping (uint => uint) public m;
    uint[] public a;
}

contract StoreTest is Test {
    C c;

    function setUp() public {
        c = new C();
    }

//  TODO: support symbolic base slot
//  function check_store(bytes32 key, bytes32 value) public {
//      vm.store(address(c), key, value);
//      assert(vm.load(address(c), key) == value);
//  }

//  TODO: support uninitialized accounts
//  function check_store_Uninit(bytes32 value) public {
//      vm.store(address(0), 0, value);
//      assert(vm.load(address(0), 0) == value);
//  }

    function check_store_Scalar(uint value) public {
        vm.store(address(c), 0, bytes32(value));
        assert(c.x() == value);
        assert(uint(vm.load(address(c), 0)) == value);
    }

    function check_store_Mapping(uint key, uint value) public {
        vm.store(address(c), keccak256(abi.encode(key, 1)), bytes32(value));
        assert(c.m(key) == value);
        assert(uint(vm.load(address(c), keccak256(abi.encode(key, 1)))) == value);
    }

    function check_store_Array(uint key, uint value) public {
        vm.assume(key < 2**32); // to avoid overflow
        vm.store(address(c), bytes32(uint(2)), bytes32(uint(1) + key));
        vm.store(address(c), bytes32(uint(keccak256(abi.encode(2))) + key), bytes32(value));
        assert(c.a(key) == value);
        assert(uint(vm.load(address(c), bytes32(uint(keccak256(abi.encode(2))) + key))) == value);
    }
}
