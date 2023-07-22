// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract HalmosCheatCodeTest is SymTest {
    function check_createUint() public {
        uint x = svm.createUint(256, 'x');
        uint y = svm.createUint(160, 'y');
        uint z = svm.createUint(8, 'z');
        assert(0 <= x && x <= type(uint256).max);
        assert(0 <= y && y <= type(uint160).max);
        assert(0 <= z && z <= type(uint8).max);
    }

    function check_createBytes() public {
        bytes memory data = svm.createBytes(2, 'data');
        uint x = uint(uint8(data[0]));
        uint y = uint(uint8(data[1]));
        assert(0 <= x && x <= type(uint8).max);
        assert(0 <= y && y <= type(uint8).max);
    }

    function check_createUint256() public {
        uint x = svm.createUint256('x');
        assert(0 <= x && x <= type(uint256).max);
    }

    function check_createBytes32() public {
        bytes32 x = svm.createBytes32('x');
        assert(0 <= uint(x) && uint(x) <= type(uint256).max);
        uint y; assembly { y := x }
        assert(0 <= y && y <= type(uint256).max);
    }

    function check_createAddress() public {
        address x = svm.createAddress('x');
        uint y; assembly { y := x }
        assert(0 <= y && y <= type(uint160).max);
    }

    function check_createBool() public {
        bool x = svm.createBool('x');
        uint y; assembly { y := x }
        assert(y == 0 || y == 1);
    }

    function check_SymbolLabel() public returns (uint256) {
        uint x = svm.createUint256('');
        uint y = svm.createUint256(' ');
        uint z = svm.createUint256(' a ');
        uint w = svm.createUint256(' a b ');
        return x + y + z + w;
    }

    function check_FailUnknownCheatcode() public {
        Dummy(address(svm)).foo(); // expected to fail with unknown cheatcode
    }
}

interface Dummy {
    function foo() external;
}
