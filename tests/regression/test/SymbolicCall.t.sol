// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract C {
    function foo() public pure returns (bool) {
        return true;
    }
}

contract SymbolicCallTest is Test {
    C c1;
    C c2;

    function setUp() public {
        c1 = new C();
        c2 = new C();
    }

    function check_foo(address addr) public {
        (bool success,) = addr.call(abi.encodeWithSelector(C.foo.selector));
        // this will fail if addr could be aliased to the test contract
        assertTrue(success);
    }

    function foo() public pure returns (bool) {
        revert();
    }
}
