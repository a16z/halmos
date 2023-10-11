// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract C {
    uint public num;

    function set(uint x) public {
        num = x;
    }
}

contract CallAliasTest is Test {
    C c1;
    C c2;

    function setUp() public {
        c1 = new C();
        c2 = new C();
    }

    function check_alias_1(address addr, uint x) public {
        if (addr == address(c1)) {
            C(addr).set(x);
            assert(c1.num() == x);
            assert(c2.num() == 0);
        } else if (addr == address(c2)) {
            C(addr).set(x);
            assert(c1.num() == 0);
            assert(c2.num() == x);
        }
    }

    function check_alias_2(address addr, uint x) public {
        if (addr == address(c1)) {
            assert(addr.codehash == address(c1).codehash);
            assert(addr.code.length == address(c1).code.length);
            assert(addr.code.length > 0);
        } else if (addr == address(this)) {
            assert(addr.codehash == address(this).codehash);
            assert(addr.code.length == address(this).code.length);
            assert(addr.code.length > 0);
        }
    }

    function check_alias_3(address addr, uint x) public {
        if (addr == address(c1)) {
            vm.store(addr, bytes32(0), bytes32(x));
            assert(c1.num() == x);
            assert(c2.num() == 0);
            assert(uint(vm.load(addr, bytes32(0))) == x);
        } else if (addr == address(c2)) {
            vm.store(addr, bytes32(0), bytes32(x));
            assert(c1.num() == 0);
            assert(c2.num() == x);
            assert(uint(vm.load(addr, bytes32(0))) == x);
        }
    }

    function check_alias_1a(bool mode, address addr, uint x) public {
        if (mode) {
            vm.assume(addr == address(c1));
        } else {
            vm.assume(addr == address(c2));
        }

        C(addr).set(x);

        if (mode) {
            assert(c1.num() == x);
            assert(c2.num() == 0);
        } else {
            assert(c1.num() == 0);
            assert(c2.num() == x);
        }
    }

    function check_alias_2a(bool mode, address addr, uint x) public {
        if (mode) {
            vm.assume(addr == address(c1));
        } else {
            vm.assume(addr == address(this));
        }

        if (mode) {
            assert(addr.codehash == address(c1).codehash);
            assert(addr.code.length == address(c1).code.length);
        } else {
            assert(addr.codehash == address(this).codehash);
            assert(addr.code.length == address(this).code.length);
        }

        assert(addr.code.length > 0);
    }

    function check_alias_3a(bool mode, address addr, uint x) public {
        if (mode) {
            vm.assume(addr == address(c1));
        } else {
            vm.assume(addr == address(c2));
        }

        vm.store(addr, bytes32(0), bytes32(x));

        if (mode) {
            assert(c1.num() == x);
            assert(c2.num() == 0);
        } else {
            assert(c1.num() == 0);
            assert(c2.num() == x);
        }

        assert(uint(vm.load(addr, bytes32(0))) == x);
    }
}
