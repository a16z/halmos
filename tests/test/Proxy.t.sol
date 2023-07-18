pragma solidity ^0.8.19;

import "forge-std/Test.sol";

import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract C {
    uint public num;
    function foo(uint x) public {
        num = x;
    }
}

contract ProxyTest is Test {
    C cImpl;
    C c;

    function setUp() public {
        cImpl = new C();
        c = C(address(new ERC1967Proxy(address(cImpl), "")));
    }

    function checkFoo(uint x) public {
        c.foo(x);
        assert(c.num() == x); // currently unsupported // TODO: support DELEGATECALL
        assert(cImpl.num() == 0);
    }
}
