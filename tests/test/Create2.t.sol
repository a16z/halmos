// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract C {
    uint public num1;
    uint public num2;

    constructor(uint x, uint y) {
        set(x, y);
    }

    function set(uint x, uint y) public {
        num1 = x;
        num2 = y;
    }
}

contract Create2Test is Test {
    function check_create2(uint x, uint y, bytes32 salt) public {
        C c1 = new C{salt: salt}(x, y);

        bytes32 codeHash = keccak256(abi.encodePacked(type(C).creationCode, abi.encode(x, y)));
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), address(this), salt, codeHash));
        address c2 = address(uint160(uint(hash)));

        assert(address(c1) == c2);

        assert(C(c2).num1() == x);
        assert(C(c2).num2() == y);

        c1.set(y, x);

        assert(C(c2).num1() == y);
        assert(C(c2).num2() == x);
    }

    function check_create2_caller(address caller, uint x, uint y, bytes32 salt) public {
        vm.prank(caller);
        C c1 = new C{salt: salt}(x, y);

        bytes32 codeHash = keccak256(abi.encodePacked(type(C).creationCode, abi.encode(x, y)));
        bytes32 hash = keccak256(abi.encodePacked(bytes1(0xff), caller, salt, codeHash));
        address c2 = address(uint160(uint(hash)));

        assert(address(c1) == c2);

        assert(C(c2).num1() == x);
        assert(C(c2).num2() == y);

        c1.set(y, x);

        assert(C(c2).num1() == y);
        assert(C(c2).num2() == x);
    }
}
