// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract Beep {
    function boop() public pure returns (uint256) {
        return 42;
    }
}

contract HalmosCheatCodeTest is SymTest, Test {
    function check_createUint() public {
        uint x = svm.createUint(256, 'x');
        uint y = svm.createUint(160, 'y');
        uint z = svm.createUint(8, 'z');
        assert(0 <= x && x <= type(uint256).max);
        assert(0 <= y && y <= type(uint160).max);
        assert(0 <= z && z <= type(uint8).max);
    }

    function check_createInt() public {
        int x = svm.createInt(256, 'x');
        int y = svm.createInt(160, 'y');
        int z = svm.createInt(8, 'z');
        assert(type(int256).min <= x && x <= type(int256).max);
        assert(type(int160).min <= y && y <= type(int160).max);
        assert(type(int8).min <= z && z <= type(int8).max);
    }

    function check_createBytes() public {
        bytes memory data = svm.createBytes(2, 'data');
        uint x = uint(uint8(data[0]));
        uint y = uint(uint8(data[1]));
        assert(0 <= x && x <= type(uint8).max);
        assert(0 <= y && y <= type(uint8).max);
    }

    function check_createString() public {
        string memory data = svm.createString(5, 'str');
        assert(bytes(data).length == 5);
    }

    function check_createUint256() public {
        uint x = svm.createUint256('x');
        assert(0 <= x && x <= type(uint256).max);
    }

    function check_createInt256() public {
        int x = svm.createInt256('x');
        assert(type(int256).min <= x && x <= type(int256).max);
    }

    function check_createBytes32() public {
        bytes32 x = svm.createBytes32('x');
        assert(0 <= uint(x) && uint(x) <= type(uint256).max);
        uint y; assembly { y := x }
        assert(0 <= y && y <= type(uint256).max);
    }

    function check_createBytes4_basic() public {
        bytes4 x = svm.createBytes4('x');

        uint256 r;
        assembly {
            r := returndatasize()
        }
        assert(r == 32);

        uint256 x_uint = uint256(uint32(x));
        assertLe(x_uint, type(uint32).max);
        uint y; assembly { y := x }
        assertLe(y, type(uint256).max);
    }

    /// @dev we expect a counterexample
    ///      (meaning that createBytes4 is able to find the selector for boop())
    function check_createBytes4_finds_selector() public {
        Beep beep = new Beep();

        bytes4 selector = svm.createBytes4("selector");
        (bool succ, bytes memory ret) = address(beep).call(abi.encode(selector));
        vm.assume(succ);
        uint256 val = abi.decode(ret, (uint256));

        assertNotEq(val, 42);
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
