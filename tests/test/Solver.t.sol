// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

// from https://github.com/a16z/halmos/issues/57

/// @custom:halmos --print-potential-counterexample --solver-timeout-assertion 10000
contract SolverTest {

    function foo(uint x) public pure returns (uint) {
        if(x < type(uint128).max)
            return x * 42;
        else return x;
    }

    function check_foo(uint a, uint b) public pure {
        if(b > a) {
            assert(foo(b) > foo(a));
        }
    }

}
