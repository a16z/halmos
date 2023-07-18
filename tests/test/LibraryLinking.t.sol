// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

library Lib {
    function foo() public pure returns (uint) { return 1; }
    function bar() internal pure returns (uint) { return 2; }
}

contract LibTest {
    function checkFoo() public pure {
        assert(Lib.foo() == 1); // library linking placeholder error
    }
}

contract LibTest2 {
    function checkBar() public pure {
        assert(Lib.bar() == 2); // this is fine because internal library functions are inlined
    }
}
