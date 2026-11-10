// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract DeepTraceRec {
    function rec(uint256 n) external returns (uint256) {
        if (n == 0) return 0;
        return this.rec(n - 1) + 1;
    }
}

/// branching after a deep call tree copies the call context, which recursed once per
/// level of nested calls until a RecursionError (halmos#416)
contract DeepTraceTest {
    function check_deep_trace(uint256 x) public {
        DeepTraceRec r = new DeepTraceRec();
        uint256 d = r.rec(600);
        if (x > 10) assert(d == 600);
        else assert(d + x >= 600);
    }
}
