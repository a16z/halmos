// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract C {
    uint public num;
    function foo(uint x) public payable returns (address, uint, address) {
        if (x > 0) num = x;
        return (msg.sender, msg.value, address(this));
    }
}

contract D {
    uint public num;
    C public c;

    constructor () {
        c = new C();
    }

    function call_foo(uint x) public payable returns (bool success, bytes memory retdata) {
        (success, retdata) = address(c).call{ value: msg.value }(abi.encodeWithSelector(c.foo.selector, x));
    }

    function staticcall_foo(uint x) public payable returns (bool success, bytes memory retdata) {
        (success, retdata) = address(c).staticcall(abi.encodeWithSelector(c.foo.selector, x));
    }

    function delegatecall_foo(uint x) public payable returns (bool success, bytes memory retdata) {
        (success, retdata) = address(c).delegatecall(abi.encodeWithSelector(c.foo.selector, x));
    }

    function callcode_foo(uint x) public payable returns (bool success, bytes memory retdata) {
        address msg_sender;
        uint msg_value;
        address target;

        bytes4 sig = c.foo.selector;

        assembly {
            let m := mload(0x40)
            mstore(m, sig)
            mstore(add(m, 0x04), x)
            success := callcode(gas(), sload(c.slot), callvalue(), m, 0x24, m, 0x60)
            msg_sender := mload(m)
            msg_value := mload(add(m, 0x20))
            target := mload(add(m, 0x40))
        }

        retdata = abi.encode(msg_sender, msg_value, target);
    }
}

contract CallTest is Test {
    D d;

    function setUp() public {
        d = new D();
    }

    function check_call(uint x, uint fund) public payable {
        vm.deal(address(this), fund);
        vm.deal(address(d), 0);
        vm.deal(address(d.c()), 0);

        (bool success, bytes memory retdata) = d.call_foo{ value: fund }(x);
        vm.assume(success);
        (address msg_sender, uint msg_value, address target) = abi.decode(retdata, (address, uint, address));

        assert(msg_sender == address(d));
        assert(msg_value == fund);
        assert(target == address(d.c()));

        assert(d.num() == 0);
        assert(d.c().num() == x);

        assert(address(this).balance == 0);
        assert(address(d).balance == 0);
        assert(address(d.c()).balance == fund);
    }

    function check_staticcall(uint x, uint fund) public payable {
        vm.deal(address(this), fund);
        vm.deal(address(d), 0);
        vm.deal(address(d.c()), 0);

        (bool success, bytes memory retdata) = d.staticcall_foo{ value: fund }(x);
        vm.assume(success);
        (address msg_sender, uint msg_value, address target) = abi.decode(retdata, (address, uint, address));

        assert(msg_sender == address(d));
        assert(msg_value == 0); // no fund transfer for staticcall
        assert(target == address(d.c()));

        assert(d.num() == 0);
        assert(d.c().num() == x);

        assert(address(this).balance == 0);
        assert(address(d).balance == fund);
        assert(address(d.c()).balance == 0);
    }

    function check_delegatecall(uint x, uint fund) public payable {
        vm.deal(address(this), fund);
        vm.deal(address(d), 0);
        vm.deal(address(d.c()), 0);

        (bool success, bytes memory retdata) = d.delegatecall_foo{ value: fund }(x);
        vm.assume(success);
        (address msg_sender, uint msg_value, address target) = abi.decode(retdata, (address, uint, address));

        // delegatecall is executed in the caller's context
        assert(msg_sender == address(this));
        assert(msg_value == fund);
        assert(target == address(d));

        assert(d.num() == x); // delegatecall updates the caller's state 
        assert(d.c().num() == 0);

        assert(address(this).balance == 0);
        assert(address(d).balance == fund); // no fund transfer for delegatecall
        assert(address(d.c()).balance == 0);
    }

    function check_callcode(uint x, uint fund) public payable {
        vm.deal(address(this), fund);
        vm.deal(address(d), 0);
        vm.deal(address(d.c()), 0);

        (bool success, bytes memory retdata) = d.callcode_foo{ value: fund }(x);
        vm.assume(success);
        (address msg_sender, uint msg_value, address target) = abi.decode(retdata, (address, uint, address));

        assert(msg_sender == address(d));
        assert(msg_value == fund);
        assert(target == address(d)); // callcode calls to itself

        assert(d.num() == x); // callcode updates the caller's state
        assert(d.c().num() == 0);

        assert(address(this).balance == 0);
        assert(address(d).balance == fund); // fund is transfered to itself
        assert(address(d.c()).balance == 0);
    }
}
