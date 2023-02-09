// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "src/Counter.sol";

contract CounterTest is Counter {
    function testSet(uint n) public {
        set(n);
        assert(cnt == n);
    }

    function testInc() public {
        uint oldCnt = cnt;
        inc();
        assert(cnt > oldCnt);
        assert(cnt == oldCnt + 1);
    }

    function testIncOpt() public {
        uint oldCnt = cnt;
        require(cnt < type(uint).max);
        incOpt();
        assert(cnt > oldCnt);
        assert(cnt == oldCnt + 1);
    }

    function testIncBy(uint n) public {
        uint oldCnt = cnt;
        incBy(n);
        assert(cnt < oldCnt || cnt == oldCnt + n); // cnt >= oldCnt ==> cnt == oldCnt + n
    }

    function specLoopFor(uint n) public {
        uint oldCnt = cnt;
        loopFor(n);
        assert(cnt >= oldCnt);
        assert(cnt == oldCnt + n);
    }
    function testLoopFor(uint8 k) public {
        specLoopFor(k);
    }

    function specLoopWhile(uint n) public {
        uint oldCnt = cnt;
        loopWhile(n);
        assert(cnt >= oldCnt);
        assert(cnt == oldCnt + n);
    }
    function testLoopWhile(uint8 k) public {
        specLoopWhile(k);
    }

    function specLoopDoWhile(uint n) public {
        uint oldCnt = cnt;
        loopDoWhile(n);
        assert(cnt > oldCnt);
        if (n == 0) assert(cnt == oldCnt + 1);
        else assert(cnt == oldCnt + n);
    }
    function testLoopDoWhile(uint8 k) public {
        specLoopDoWhile(k);
    }

    function testLoopConst() public {
        uint oldCnt = cnt;
        loopConst();
        assert(cnt >= oldCnt);
        assert(cnt == oldCnt + 4);
    }

    function testLoopConstIf() public {
        uint oldCnt = cnt;
        loopConstIf();
        assert(cnt >= oldCnt);
        assert(cnt <= oldCnt + 4);
    }

    function specSetSum(uint[2] memory arr) public {
        setSum(arr);
        assert(cnt == arr[0] + arr[1]);
    }
    function testSetSum(uint248 a, uint248 b) public {
        specSetSum([uint(a), b]);
    }

    function testSetString(uint, string memory s, uint, string memory r, uint) public {
        uint oldCnt = cnt;
        setString(s);
        setString(r);
        assert(cnt == oldCnt + bytes(s).length + bytes(r).length);
    }

    function testFoo(uint a, uint b, uint c, uint d) public {
        uint oldCnt = cnt;
        foo(a, b, c, d);
        assert(cnt == oldCnt + 4);
    }

    function testDiv1(uint x, uint y) public pure {
        if (y > 0) {
            assert(x / y <= x);
        }
    }

    function testDiv2(uint x, uint y) public pure {
        if (y > 0) {
            assert(x / y == x / y);
        }
    }

    function testMulDiv(uint x, uint y) public pure {
        unchecked {
            if (x > 0 && y > 0) {
                uint z = x * y;
                if (z / x == y) {
                    assert(z / x == y);
                  //assert(z / y == x); // smt failed to solve
                }
            }
        }
    }

    function testFail() public pure {
        require(false);
        // deadcode
    }
}
