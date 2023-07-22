// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

library Math {
    function add(uint x, uint y) public pure returns (uint) {
        return _add(x,y);
    }

    function _add(uint x, uint y) internal pure returns (uint) {
        unchecked {
            return x + y;
        }
    }
}

contract LibraryTest {
    function check_add(uint x, uint y) public pure {
        unchecked {
            assert(Math._add(x,y) == x+y);
            /* TODO: support public library functions (library linking)
            assert(Math.add(x,y) == x+y);
            */
        }
    }
}
