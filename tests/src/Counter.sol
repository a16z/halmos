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

    function loop(uint n) public {
        for (uint i; i < n; i++) {
            cnt++;
        }
    }

    function setSum(uint[2] memory arr) public {
        cnt = arr[0] + arr[1];
    }

    function setString(string memory s) public {
        cnt += bytes(s).length;
    }
}
