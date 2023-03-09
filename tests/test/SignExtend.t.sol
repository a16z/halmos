// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/SignExtend.sol";

contract SignExtendTest is SignExtend {
    function testSignExtend() public pure {
        int x = changeMySign(3);
        assert(x == -3);
    }
}
