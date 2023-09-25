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

    function _check_deposit(uint a, uint A1, uint S1) public pure returns (bool) {
        uint s = (a * S1) / A1;

        uint A2 = A1 + a;
        uint S2 = S1 + s;

        return (A1 / S1 <= A2 / S2); // always true
    }

    // NOTE: currently timeout when --smt-div is enabled; producing invalid counterexamples when --smt-div is not given
    function check_deposit(uint a, uint A1, uint S1) public pure {
        assert(_check_deposit(a, A1, S1)); // no counterexample
    }

    function test_deposit(uint a, uint A1, uint S1) public {
        (bool success, bytes memory retdata) = address(this).call(abi.encodeWithSelector(this._check_deposit.selector, a, A1, S1));
        if (!success) return;
        assert(abi.decode(retdata, (bool)));
    }

    function _check_mint(uint s, uint A1, uint S1) public pure returns (bool) {
        uint a = (s * A1) / S1;

        uint A2 = A1 + a;
        uint S2 = S1 + s;

        // (A1 / S1 <= A2 / S2)
        return (A1 * S2 <= A2 * S1); // can be false
    }

    /// @custom:halmos --smt-div
    function check_mint(uint s, uint A1, uint S1) public pure {
        assert(_check_mint(s, A1, S1)); // counterexamples exist
    }

    function test_mint(uint s, uint A1, uint S1) public {
        (bool success, bytes memory retdata) = address(this).call(abi.encodeWithSelector(this._check_mint.selector, s, A1, S1));
        if (!success) return;
        assert(abi.decode(retdata, (bool)));
    }
}
