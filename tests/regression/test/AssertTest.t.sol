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

contract AssertTest is Test {
    C c;

    function setUp() public {
        c = new C();
    }

    function check_assert_not_propagated() public {
        address(c).call(abi.encodeWithSelector(C.foo.selector, bytes(""))); // pass
    }

    function check_fail_propagated() public {
        address(c).call(abi.encodeWithSelector(C.bar.selector, bytes(""))); // fail
    }

    function check_symbolic_revert(uint256 x) public {
        // reverts with Concat(0x4e487b71, p_x_uint256())
        // halmos only considers reverts with explicit revert codes so we expect a PASS here
        // this is really to make sure we handle symbolic reverts gracefully
        if (x > 0) {
            bytes memory data = abi.encodeWithSignature("Panic(uint256)", x);
            assembly {
                revert(add(data, 0x20), mload(data))
            }
        }
    }
}
