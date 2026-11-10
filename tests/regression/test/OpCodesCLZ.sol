// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.24 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

// =============================================================================
// CLZ (0x1E) — Count Leading Zeros (EIP-7939 / Fusaka)
// =============================================================================


contract ClzTest is SymTest, Test {

    function check_clz_zero() public pure {
        uint256 result;
        assembly { result := clz(0) }
        assert(result == 256);
    }

    function check_clz_one() public pure {
        uint256 result;
        assembly { result := clz(1) }
        assert(result == 255);
    }

    function check_clz_two() public pure {
        uint256 result;
        assembly { result := clz(2) }
        assert(result == 254);
    }

    function check_clz_msb() public pure {
        // 2^255 
        uint256 x = 1 << 255;
        uint256 result;
        assembly { result := clz(x) }
        assert(result == 0);
    }

    function check_clz_max() public pure {
        // type(uint256).max
        uint256 x = type(uint256).max;
        uint256 result;
        assembly { result := clz(x) }
        assert(result == 0);
    }

    function check_clz_byte() public pure {
        // 0xFF = 8 bits → 256 - 8 = 248 zéros
        uint256 result;
        assembly { result := clz(0xFF) }
        assert(result == 248);
    }

    // -------------------------------------------------------------------------
    // Formal properties of the CLZ opcode
    // -------------------------------------------------------------------------

    /// clz(0) == 256
    function check_clz_zero_symbolic() public pure {
        uint256 x = 0;
        uint256 result;
        assembly { result := clz(x) }
        assert(result == 256);
    }

    ///  x != 0 : clz(x) ∈ [0, 255]
    function check_clz_range(uint256 x) public pure {
        if (x == 0) return;
        uint256 result;
        assembly { result := clz(x) }
        assert(result <= 255);
    }

    ///  x != 0 : 2^(255 - clz(x)) <= x 
    function check_clz_lower_bound(uint256 x) public pure {
        if (x == 0) return;
        uint256 c;
        assembly { c := clz(x) }
        assert((uint256(1) << (255 - c)) <= x);
    }

    ///  x != 0 et clz(x) > 0 : x < 2^(256 - clz(x))
    function check_clz_upper_bound(uint256 x) public pure {
        if (x == 0) return;
        uint256 c;
        assembly { c := clz(x) }
        if (c > 0) {
            assert(x < (uint256(1) << (256 - c)));
        }
    }

    /// clz(2^k) == 255 - k pour k ∈ [0, 255]
    function check_clz_power_of_two(uint8 k) public pure {
        if (k > 255) return;
        uint256 p = uint256(1) << k;
        uint256 result;
        assembly { result := clz(p) }
        assert(result == 255 - uint256(k));
    }

    /// Monotony : a <= b ⟹ clz(a) >= clz(b)
    function check_clz_monotone(uint256 a, uint256 b) public pure {
        if (a == 0 || b == 0) return;
        if (a <= b) {
            uint256 ca; uint256 cb;
            assembly {
                ca := clz(a)
                cb := clz(b)
            }
            assert(ca >= cb);
        }
    }

}
