// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract SortMismatchTest is SymTest, Test {
    uint256 public fortytwo = 42;

    function does_revert() public {
        // trying to trigger `Encountered symbolic return data size: True`
        uint256 z = this.fortytwo();
        assembly {
            let cond := eq(z, 42)
            revert(0, cond)
        }
    }

    function check_revert() external {
        try this.does_revert() {
            // it should have reverted
            assert(false);
        } catch {
            // all good
        }
    }

    function check_return() external {
        // trying to trigger `Encountered symbolic return data size: True`
        uint256 z = this.fortytwo();
        assembly {
            let cond := eq(z, 42)
            return(0, cond)
        }
    }

    // arithmetic

    function check_add(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := add(x, cond)
        }
    }

    function check_mul(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := mul(x, cond)
        }
    }

    function check_sub(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := sub(x, cond)
        }
    }

    function check_div(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := div(x, cond)
        }
    }

    function check_sdiv(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := sdiv(x, cond)
        }
    }

    function check_mod(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := mod(x, cond)
        }
    }

    function check_smod(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := smod(x, cond)
        }
    }

    function check_addmod(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := addmod(x, cond, 100)
        }
    }

    function check_mulmod(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := mulmod(x, cond, 100)
        }
    }

    function check_exp(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := exp(x, cond)
        }
    }

    // comparison

    function check_lt(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := lt(x, cond)
        }
    }

    function check_gt(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := gt(x, cond)
        }
    }

    function check_slt(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := slt(x, cond)
        }
    }

    function check_sgt(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := sgt(x, cond)
        }
    }

    function check_eq(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := eq(x, cond)
        }
    }

    function check_iszero(uint256 x) external returns (uint256 y) {
        uint256 z = this.fortytwo();
        assembly {
            let cond := eq(z, 42)
            y := iszero(cond)
        }
    }

    // bitwise

    function check_and(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := and(x, cond)
        }
    }

    function check_or(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := or(x, cond)
        }
    }

    function check_xor(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := xor(x, cond)
        }
    }

    function check_not(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := not(cond)
        }
    }

    function check_shl(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := shl(x, cond)
        }
    }

    function check_sar(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := sar(x, cond)
        }
    }

    function check_shr(uint256 x) external returns (uint256 y) {
        assembly {
            let cond := eq(x, 42)
            y := shr(x, cond)
        }
    }

    function check_signextend(uint256 x) external returns (uint256 y) {
        uint256 z = this.fortytwo();
        assembly {
            let cond := eq(z, 42)
            y := signextend(cond, x)
        }
    }
}

