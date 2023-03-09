// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract SignExtend {
    function changeMySign(int8 x) public pure returns (int8) {
        return -x;
    }
}
