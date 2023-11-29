// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Test} from "forge-std/Test.sol";

struct Set {
    bytes[] _values;
    mapping(bytes => uint256) _indexes;
}

library EnumerableSet {
    function add(Set storage set, bytes calldata value) internal returns (bool) {
        if (!contains(set, value)) {
            set._values.push(value);
            set._indexes[value] = set._values.length;
            return true;
        } else {
            return false;
        }
    }

    function contains(Set storage set, bytes calldata value) internal view returns (bool) {
        return set._indexes[value] != 0;
    }

    function length(Set storage set) internal view returns (uint256) {
        return set._values.length;
    }

    function at(Set storage set, uint256 index) internal view returns (bytes memory) {
        return set._values[index];
    }

    function values(Set storage set) internal view returns (bytes[] memory) {
        return set._values;
    }
}

contract Storage4 {
    using EnumerableSet for Set;

    mapping(uint256 => Set) internal map;

    function add(uint256 key, bytes calldata value) external {
        map[key].add(value);
    }

    function lookup(uint256 key) internal view returns (Set storage) {
        return map[key];
    }

    function totalValues(uint256 key) public view virtual returns (uint256) {
        return lookup(key).length();
    }

    function valueAt(uint256 key, uint256 index) external view returns (bytes memory) {
        return lookup(key).at(index);
    }

    function valuesOf(uint256 key) external view returns (bytes[] memory) {
        return lookup(key).values();
    }
}


contract Storage4Test is SymTest, Test {
    Storage4 s;

    function setUp() public {
        s = new Storage4();
    }

    function check_add_1(uint k) public {
        bytes[] memory v = new bytes[](10);

        v[1] = svm.createBytes(31, "v1");
        v[2] = svm.createBytes(32, "v2");
        v[3] = svm.createBytes(33, "v3");

        s.add(k, v[1]);
        s.add(k, v[2]);
        s.add(k, v[3]);

        assert(keccak256(s.valueAt(k, 0)) == keccak256(v[1]));
        assert(keccak256(s.valueAt(k, 1)) == keccak256(v[2]));
        assert(keccak256(s.valueAt(k, 2)) == keccak256(v[3]));

        assert(s.totalValues(k) == 3);
    }

    function check_add_2(uint k) public {
        bytes[] memory v = new bytes[](10);

        // note: v1 and v2 may be equal, since they are of the same size
        v[1] = svm.createBytes(32, "v1");
        v[2] = svm.createBytes(32, "v2");

        s.add(k, v[1]);
        s.add(k, v[2]);

        if (s.totalValues(k) == 2) {
            assert(keccak256(s.valueAt(k, 0)) == keccak256(v[1]));
            assert(keccak256(s.valueAt(k, 1)) == keccak256(v[2]));
        } else {
            assert(s.totalValues(k) == 1);

            assert(keccak256(s.valueAt(k, 0)) == keccak256(v[1]));
            assert(keccak256(s.valueAt(k, 0)) == keccak256(v[2]));

            assert(keccak256(v[1]) == keccak256(v[2]));
        }
    }
}
