// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract Sha3Test is Test, SymTest {
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

    function _assert_eq(bytes memory data1, bytes memory data2) internal {
        assert(keccak256(data1) == keccak256(data2));
    }

    function _assert_neq(bytes memory data1, bytes memory data2) internal {
        assert(keccak256(data1) != keccak256(data2));
    }
}
