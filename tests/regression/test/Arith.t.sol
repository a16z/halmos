// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract ArithTest {

    function unchecked_div(uint x, uint y) public pure returns (uint ret) {
        assembly {
            ret := div(x, y)
        }
    }

    function unchecked_mod(uint x, uint y) public pure returns (uint ret) {
        assembly {
            ret := mod(x, y)
        }
    }

    function check_Mod(uint x, uint y, address addr) public pure {
        unchecked {
            assert(unchecked_mod(x, 0) == 0); // compiler rejects `x % 0`
            assert(x % 1 == 0);
            assert(x % 2 < 2);
            assert(x % 4 < 4);

            uint x_mod_y = unchecked_mod(x, y);
        //  assert(x_mod_y == 0 || x_mod_y < y); // not supported // TODO: support more axioms
            assert(x_mod_y <= y);

            assert(uint256(uint160(addr)) % (2**160) == uint256(uint160(addr)));
        }
    }

    function check_Exp(uint x) public pure {
        unchecked {
            assert(x ** 0 == 1); // 0 ** 0 == 1
            assert(x ** 1 == x);
            assert(x ** 2 == x * x);
            assert((x ** 2) ** 2 == x * x * x * x);
            assert(((x ** 2) ** 2) ** 2 == (x**2) * (x**2) * (x**2) * (x**2));
        //  assert(x ** 8 == (x ** 4) ** 2);
        }
    }

    function check_Div_fail(uint x, uint y) public pure {
        require(x > y);

        uint q = unchecked_div(x, y);

        // note: since x > y, q can be zero only when y == 0, due to the division-by-zero semantics in the EVM

        assert(q != 0); // counterexample: y == 0
    }

    function check_Div_pass(uint x, uint y) public pure {
        require(x > y);
        require(y > 0);

        uint q = unchecked_div(x, y);

        assert(q != 0); // pass
    }
}
