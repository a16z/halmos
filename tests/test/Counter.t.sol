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

    function specLoop(uint n) public {
        uint oldCnt = cnt;
        loop(n);
        assert(cnt >= oldCnt);
        assert(cnt == oldCnt + n);
    }
    function testLoop(uint8 k) public {
        specLoop(k);
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

    function testFalse() public {
        require(false);
        // deadcode
    }
}
