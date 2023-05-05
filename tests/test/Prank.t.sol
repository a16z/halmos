// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "forge-std/StdCheats.sol";

contract PrankSetUpTest is Test {
    Target target;

    function setUp() public {
        target = new Target();
        vm.prank(address(target)); // prank is reset after setUp()
    }

    function testPrank(address user) public {
        vm.prank(user);
        target.setCaller();
        assert(target.caller() == user);
    }

}

contract PrankTest is Test {

    Target target;
    Some some;
    Dummy dummy;

    function setUp() public {
        target = new Target();
        some = new Some();
    }

    function foo(address user) public {
        vm.prank(user);
    }

    function testPrank(address user) public {
        vm.assume(user != address(this));

        vm.prank(user);
        target.setCaller();
        assert(target.caller() == user);

        target.setCaller();
        assert(target.caller() == address(this));
    }

    function testPrankInternal(address user) public {
        foo(user); // prank is still active after returning from foo()
        target.setCaller();
        assert(target.caller() == user);
    }

    function testPrankExternal(address user) public {
        some.bar(user); // prank isn't propagated beyond the vm boundry
        target.setCaller();
        assert(target.caller() == address(this));
    }

    function testPrankExternalSelf(address user) public {
        PrankTest(address(this)).foo(user); // prank isn't propagated beyond the vm boundry
        target.setCaller();
        assert(target.caller() == address(this));
    }

    function testPrankReset(address user) public {
    //  vm.prank(address(target)); // overwriting active prank is not allowed
        vm.prank(user);
        target.setCaller();
        assert(target.caller() == user);
    }

    function testPrankNew(address user) public {
        vm.prank(user);
        dummy = new Dummy(); // contract creation also consumes prank
        vm.prank(user);
        target.setCaller();
        assert(target.caller() == user);
    }
}

contract Target {
    address public caller;

    function setCaller() public {
        caller = msg.sender;
    }
}

contract Some is Test {
    function bar(address user) public {
        vm.prank(user);
    }
}

contract Dummy {
    uint public dummy;
}
