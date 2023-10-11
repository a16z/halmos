// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract MathTest {
    function check_Avg(uint a, uint b) public pure {
        unchecked {
            uint r1 = (a & b) + (a ^ b) / 2;
            uint r2 = (a + b) / 2;
            assert(r1 == r2);
        }
    }

    /// @custom:halmos --solver-timeout-assertion 10000
    function check_deposit(uint a, uint A1, uint S1) public pure {
        uint s = (a * S1) / A1;

        uint A2 = A1 + a;
        uint S2 = S1 + s;

        // (A1 / S1 <= A2 / S2)
        assert(A1 * S2 <= A2 * S1); // no counterexample
    }

    /// @custom:halmos --solver-timeout-assertion 0
    function check_mint(uint s, uint A1, uint S1) public pure {
        uint a = (s * A1) / S1;

        uint A2 = A1 + a;
        uint S2 = S1 + s;

        // (A1 / S1 <= A2 / S2)
        assert(A1 * S2 <= A2 * S1); // counterexamples exist
    }
}
