pragma solidity ^0.8.19;

import "forge-std/Test.sol";

import {ERC1967Proxy} from "openzeppelin-contracts/contracts/proxy/ERC1967/ERC1967Proxy.sol";

contract C {
    uint public num;
    function foo(uint x) public payable returns (address, uint, address) {
        num = x;
        return (msg.sender, msg.value, address(this));
    }
}

contract ProxyTest is Test {
    C cImpl;
    C c;

    function setUp() public {
        cImpl = new C();
        c = C(address(new ERC1967Proxy(address(cImpl), "")));
    }

    function check_foo(uint x, uint fund, address caller) public {
        vm.deal(caller, fund);
        vm.prank(caller);
        (address msg_sender, uint msg_value, address target) = c.foo{ value: fund }(x);
        assert(msg_sender == caller);
        assert(msg_value == fund);
        assert(target == address(c));

        assert(c.num() == x);
        assert(cImpl.num() == 0);
    }
}
