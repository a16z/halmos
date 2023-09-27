// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "../src/IsPowerOfTwo.sol";

/// @custom:halmos --solver-timeout-assertion 0
contract IsPowerOfTwoTest {
    IsPowerOfTwo target;

    function setUp() public {
        target = new IsPowerOfTwo();
    }

    function check_isPowerOfTwo_small(uint8 x) public view {
        bool result1 = target.isPowerOfTwo(x);
        bool result2 = x == 1 || x == 2 || x == 4 || x == 8 || x == 16 || x == 32 || x == 64 || x == 128;
        assert(result1 == result2);
    }

    /// @custom:halmos --loop 256
    function check_isPowerOfTwo(uint256 x) public view {
        bool result1 = target.isPowerOfTwo(x);
        bool result2 = false;
        for (uint i = 0; i < 256; i++) { // NOTE: `--loop 256` option needed for complete verification
            if (x == 2**i) {
                result2 = true;
                break;
            }
        }
        assert(result1 == result2);
    }

    /// @custom:halmos --loop 256
    function check_eq_isPowerOfTwo_isPowerOfTwoIter(uint x) public view {
        bool result1 = target.isPowerOfTwo(x);
        bool result2 = target.isPowerOfTwoIter(x);
        assert(result1 == result2);
    }
}
