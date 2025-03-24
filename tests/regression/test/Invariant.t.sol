// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {Clones} from "@openzeppelin/contracts/proxy/Clones.sol";

import "forge-std/Test.sol";

contract C {
    uint public num;

    function inc(uint x) public {
        require(x <= 2);
        num += x;
    }
}


contract InvariantTest is Test {
    C c;

    function setUp() public {
        c = new C();
    }

    function invariant_1() public {
        console.log(c.num());
        assertLe(c.num(), 4);
    }

    function invariant_2() public {
        assert(c.num() != 3);
    }
}

contract InvariantProxyTest is Test {
    C impl = new C();
    C c;

    function setUp() public {
        c = C(Clones.clone(address(impl)));
    }

    function invariant_proxy_1() public {
        console.log(c.num());
    }

    function invariant_proxy_2() public {
        assert(c.num() != 3);
    }
}
