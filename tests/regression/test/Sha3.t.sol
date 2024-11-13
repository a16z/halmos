// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract Sha3Test is Test, SymTest {
    // 0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470
    bytes32 constant EMPTY_HASH = keccak256("");

    function check_hash() public {
        _assert_eq("", "");
        _assert_eq("1", "1");

        bytes memory data = svm.createBytes(1, "data");
        _assert_eq(data, data);
    }

    function check_no_hash_collision_assumption() public {
        // assume no hash collisions

        bytes memory data1 = svm.createBytes(1, "data1");
        bytes memory data2 = svm.createBytes(2, "data2");
        _assert_neq(data1, data2);

        bytes memory data32_1 = svm.createBytes(32, "data32_1");
        bytes memory data32_2 = svm.createBytes(32, "data32_2");
        vm.assume(keccak256(data32_1) == keccak256(data32_2));
        assert(data32_1[0] == data32_2[0]);
    }

    function check_hash_collision_with_empty() public {
        bytes memory data = svm.createBytes(1, "data");
        assertNotEq(keccak256(data), keccak256(""));
    }

    function check_empty_hash_value() public {
        assertEq(keccak256(""), EMPTY_HASH);

        // TODO: uncomment when we support empty bytes
        // bytes memory data = svm.createBytes(0, "data");
        // assertEq(keccak256(data), EMPTY_HASH);
    }

    function check_only_empty_bytes_matches_empty_hash(bytes memory data) public {
        // empty hash value
        vm.assume(keccak256(data) == EMPTY_HASH);
        assertEq(data.length, 0);
    }

    function check_concrete_keccak_does_not_split_paths() external {
        bytes32 hash = keccak256("data");
        uint256 bit = uint256(hash) & 1;

        // this tests that the hash value is concrete
        // if it was symbolic, we would split paths and fail in the even case
        // (keccak("data") is odd)
        if (uint256(hash) & 1 == 0) {
            console2.log("even");
            assert(false);
        } else {
            console2.log("odd");
            assert(true);
        }
    }

    function check_concrete_keccak_memory_lookup() external {
        bytes32 hash = keccak256(abi.encodePacked(uint256(3)));
        uint256 bit = uint256(hash) & 1;

        string[] memory x = new string[](2);
        x[0] = "even";
        x[1] = "odd";

        // checks that we don't fail with symbolic memory offset error
        console2.log(x[bit]);
    }

    function _assert_eq(bytes memory data1, bytes memory data2) internal {
        assert(keccak256(data1) == keccak256(data2));
    }

    function _assert_neq(bytes memory data1, bytes memory data2) internal {
        assert(keccak256(data1) != keccak256(data2));
    }

    function check_uint256_collision(uint256 x, uint256 y) public {
        vm.assume(x != y);
        assertNotEq(keccak256(abi.encode(x)), keccak256(abi.encode(y)));
    }

    // we assume that the lower 160-bit parts do not collide
    // see: https://github.com/a16z/halmos/issues/347
    function check_address_collision_pass(uint256 x, uint256 y) public {
        vm.assume(x != y);
        assertNotEq(to_address(x), to_address(y)); // pass
    }

    function to_address(uint256 x) internal pure returns (address) {
        return address(uint160(uint256(keccak256(abi.encode(x)))));
    }

    function check_uint160_collision_pass(uint256 x, uint256 y) public {
        vm.assume(x != y);
        assertNotEq(uint160(uint256(keccak256(abi.encode(x)))), uint160(uint256(keccak256(abi.encode(y))))); // pass
    }

    // we don't rule out potential collision in the part lower than 160-bit
    function check_uint128_collision_fail(uint256 x, uint256 y) public {
        vm.assume(x != y);
        assertNotEq(uint128(uint256(keccak256(abi.encode(x)))), uint128(uint256(keccak256(abi.encode(y))))); // fail
    }
}
