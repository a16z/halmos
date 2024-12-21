// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract C /*is SymTest, Test*/ {
    D d;

    constructor () {
        d = new D();
    }

    function foo(bytes memory foo_data) public returns (bool success, bytes memory retdata) {
//        console.log(uint(keccak256(foo_data)));
        (success, retdata) = address(d).call(foo_data);
    }
}

contract D /*is SymTest, Test*/ {
    function bar(bytes memory bar_data) public returns (bytes memory) {
//        console.log(uint(keccak256(bar_data)));
        return bar_data;
    }
}

/// @custom:halmos --default-bytes-lengths 0,1024
contract BytesTest is SymTest, Test {
    C c;

    function setUp() public {
        c = new C();
    }

    function check_C() public {
        (, bytes memory retdata) = address(c).call(svm.createBytes(1024, "data"));
//        (, bytes memory retdata) = address(c).call(svm.createCalldata("Bytes.t.sol", "C"));
//        console.log(uint(keccak256(retdata)));
    }
}
