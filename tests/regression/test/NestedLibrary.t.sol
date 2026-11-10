// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

library NestedLibB {
    function triple(uint256 x) public pure returns (uint256) {
        return 3 * x;
    }
}

library NestedLibA {
    // links NestedLibB: its deployed code has NestedLibB's placeholder
    function sixfold(uint256 x) public pure returns (uint256) {
        return 2 * NestedLibB.triple(x);
    }
}

/// a library that links another library (halmos#555)
contract NestedLibraryTest {
    function check_nested_library(uint8 x) public pure {
        assert(NestedLibA.sixfold(x) == 6 * uint256(x));
    }

    function check_nested_library_fail(uint8 x) public pure {
        assert(NestedLibA.sixfold(x) != 42);
    }
}
