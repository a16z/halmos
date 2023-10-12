// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/SignExtend.sol";

contract SignExtendTest is SignExtend {
    function check_SIGNEXTEND(int16 _x) public pure {
        int16 x = changeMySign(_x);
        assert(x == -_x);
    }
}
