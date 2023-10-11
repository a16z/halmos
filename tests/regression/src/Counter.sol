// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract Counter {
    uint public cnt;

    constructor() {}

    function set(uint n) public {
        cnt = n;
    }

    function inc() public {
        cnt++;
    }

    function incOpt() public {
        unchecked {
            cnt++;
        }
    }

    function incBy(uint n) public {
        unchecked {
            cnt += n;
        }
    }

    function loopFor(uint n) public {
        for (uint i; i < n; i++) {
            cnt++;
        }
    }

    function loopWhile(uint n) public {
        uint i = 0;
        while (i < n) {
            cnt++;
            i++;
        }
    }

    function loopDoWhile(uint n) public {
        uint i = 0;
        do {
            cnt++;
        } while (++i < n);
    }

    function loopConst() public {
        for (uint i; i < 2; i++) { // default: `--loop 2`
            cnt++;
        }
    }

    mapping (uint => bool) map;
    function loopConstIf() public {
        // total # of paths is 16 (= 2^4), but only 6 (= 4C2) of them will be considered if `--loop 2` is given
        for (uint i; i < 4; i++) {
            if (map[i]) cnt++;
        }
    }

    function setSum(uint[2] memory arr) public {
        cnt = arr[0] + arr[1];
    }

    function setString(string memory s) public {
        cnt += bytes(s).length;
    }

    function foo(uint a, uint b, uint c, uint d) public {
        bar(a);
        bar(b);
        bar(c);
        bar(d);
    }

    function bar(uint x) public {
        if (x > 10) cnt++;
        else cnt++;
    }
}
