// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

/// signed wadMul edge case in solmate:
/// https://twitter.com/transmissions11/status/1688601302371389440
/// https://twitter.com/milotruck/status/1691136777749512192
/// https://twitter.com/Montyly/status/1688603604062482433

interface WadMul {
    function wadMul(int256 x, int256 y) external pure returns (int256);
}

contract SolmateBadWadMul is WadMul {
    // https://github.com/transmissions11/solmate/blob/main/src/utils/SignedWadMath.sol
    // after the fix (fadb2e2778adbf01c80275bfb99e5c14969d964b)
    function wadMul(int256 x, int256 y) public pure override returns (int256 r) {
        /// @solidity memory-safe-assembly
        assembly {
            // Store x * y in r for now.
            r := mul(x, y)

            // Equivalent to require(x == 0 || (x * y) / x == y)
            if iszero(or(iszero(x), eq(sdiv(r, x), y))) { revert(0, 0) }

            // Scale the result down by 1e18.
            r := sdiv(r, 1000000000000000000)
        }
    }
}

contract SolmateGoodWadMul is WadMul {
    // https://github.com/transmissions11/solmate/blob/main/src/utils/SignedWadMath.sol
    // after the fix (fadb2e2778adbf01c80275bfb99e5c14969d964b)
    function wadMul(int256 x, int256 y) public pure override returns (int256 r) {
        /// @solidity memory-safe-assembly
        assembly {
            // Store x * y in r for now.
            r := mul(x, y)

            // Combined overflow check (`x == 0 || (x * y) / x == y`) and edge case check
            // where x == -1 and y == type(int256).min, for y == -1 and x == min int256,
            // the second overflow check will catch this.
            // See: https://secure-contracts.com/learn_evm/arithmetic-checks.html#arithmetic-checks-for-int256-multiplication
            // Combining into 1 expression saves gas as resulting bytecode will only have 1 `JUMPI`
            // rather than 2.
            if iszero(
                and(
                    or(iszero(x), eq(sdiv(r, x), y)),
                    or(lt(x, not(0)), sgt(y, 0x8000000000000000000000000000000000000000000000000000000000000000))
                )
            ) { revert(0, 0) }

            // Scale the result down by 1e18.
            r := sdiv(r, 1000000000000000000)
        }
    }
}

contract SolidityWadMul is WadMul {
    function wadMul(int256 x, int256 y) public pure override returns (int256) {
        return (x * y) / 1e18;
    }
}

abstract contract TestMulWad is Test {
    WadMul wadMul;
    SolidityWadMul solidityWadMul = new SolidityWadMul();

    function setUp() external {
        solidityWadMul = new SolidityWadMul();
        wadMul = createWadMul();
    }

    function createWadMul() internal virtual returns (WadMul);

    /// @custom:halmos --smt-div
    function check_wadMul_solEquivalent(int256 x, int256 y) external {
        bytes memory encodedCall = abi.encodeWithSelector(WadMul.wadMul.selector, x, y);

        (bool succ1, bytes memory retbytes1) = address(solidityWadMul).call(encodedCall);
        (bool succ2, bytes memory retbytes2) = address(wadMul).call(encodedCall);

        // if one reverts, the other should too
        assertEq(succ1, succ2);

        if (succ1 && succ2) {
            // if both succeed, they should return the same value
            int256 result1 = abi.decode(retbytes1, (int256));
            int256 result2 = abi.decode(retbytes2, (int256));
            assertEq(result1, result2);
        }
    }
}

contract TestBadWadMul is TestMulWad {
    /// @dev there is an edge case, so we expect this to fail with:
    // Counterexample:
    //     p_x_int256 = 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
    //     p_y_int256 = 0x8000000000000000000000000000000000000000000000000000000000000000
    function createWadMul() internal override returns (WadMul) {
        return new SolmateBadWadMul();
    }
}

contract TestGoodWadMul is TestMulWad {
    function createWadMul() internal override returns (WadMul) {
        return new SolmateGoodWadMul();
    }
}
