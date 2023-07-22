// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract C is Test {
    function foo() public pure {
        assert(false); // not propagated
    }

    function bar() public {
        fail(); // propagated
    }
}

contract CTest is Test {
    C c;

    function setUp() public {
        c = new C();
    }

    function check_foo() public {
        address(c).call(abi.encodeWithSelector(C.foo.selector, bytes(""))); // pass
    }

    function check_bar() public {
        address(c).call(abi.encodeWithSelector(C.bar.selector, bytes(""))); // fail
    }
}
