// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract IsPowerOfTwo {

    function isPowerOfTwo(uint x) public pure returns (bool) {
        unchecked {
            return x != 0 && (x & (x - 1)) == 0;
        }
    }

    function isPowerOfTwoIter(uint x) public pure returns (bool) {
        unchecked {
            while (x != 0 && (x & 1) == 0) x >>= 1; // NOTE: `--loop 256` option needed for complete verification
            return x == 1;
        }
    }

}
