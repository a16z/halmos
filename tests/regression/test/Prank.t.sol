// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract Dummy { }

contract Target {
    address public caller;

    function setCaller(address addr) public {
        caller = addr;
    }

    function recordCaller() public {
        caller = msg.sender;
    }
}

contract ConstructorRecorder {
    address public caller;

    constructor() {
        caller = msg.sender;
    }
}

contract Ext is Test {
    function prank(address user) public {
        vm.prank(user);
    }
}

contract PrankSetUpTest is Test {
    Target target;

    function setUp() public {
        target = new Target();
        vm.prank(address(target)); // prank is reset after setUp()
    }

    function check_prank(address user) public {
        vm.prank(user);
        target.recordCaller();
        assert(target.caller() == user);
    }
}

contract PrankTest is Test {
    Target target;
    Ext ext;
    Dummy dummy;

    function setUp() public {
        target = new Target();
        ext = new Ext();
    }

    function prank(address user) public {
        vm.prank(user);
    }

    function check_prank(address user) public {
        vm.prank(user);
        target.recordCaller();
        assert(target.caller() == user);

        target.recordCaller();
        assert(target.caller() == address(this));
    }

    function check_startPrank(address user) public {
        vm.startPrank(user);

        target.recordCaller();
        assert(target.caller() == user);

        target.setCaller(address(this));
        assert(target.caller() == address(this));

        target.recordCaller();
        assert(target.caller() == user);

        vm.stopPrank();

        target.recordCaller();
        assert(target.caller() == address(this));
    }

    function check_prank_Internal(address user) public {
        prank(user); // indirect prank
        target.recordCaller();
        assert(target.caller() == user);
    }

    function check_prank_External(address user) public {
        ext.prank(user); // prank isn't propagated beyond the vm boundry
        target.recordCaller();
        assert(target.caller() == address(this));
    }

    function check_prank_ExternalSelf(address user) public {
        this.prank(user); // prank isn't propagated beyond the vm boundry
        target.recordCaller();
        assert(target.caller() == address(this));
    }

    function check_prank_New(address user) public {
        vm.prank(user);
        dummy = new Dummy(); // contract creation also consumes prank
        vm.prank(user);
        target.recordCaller();
        assert(target.caller() == user);
    }

    function check_prank_Reset1(address user) public {
    //  vm.prank(address(target)); // overwriting active prank is not allowed
        vm.prank(user);
        target.recordCaller();
        assert(target.caller() == user);
    }

    function check_prank_Reset2(address user) public {
    //  vm.prank(address(target)); // overwriting active prank is not allowed
        vm.startPrank(user);
        target.recordCaller();
        assert(target.caller() == user);
    }

    function check_stopPrank_1(address user) public {
        vm.prank(user);
        vm.stopPrank(); // stopPrank can be used to disable both startPrank() and prank()
        target.recordCaller();
        assert(target.caller() == address(this));
    }

    function check_stopPrank_2() public {
        vm.stopPrank(); // stopPrank is allowed even when no active prank exists!
        target.recordCaller();
        assert(target.caller() == address(this));
    }

    function check_prank_Constructor(address user) public {
        vm.prank(user);
        ConstructorRecorder recorder = new ConstructorRecorder();
        assert(recorder.caller() == user);
    }

    // TODO: uncomment when we add CREATE2 support
    // function check_prank_ConstructorCreate2(address user, bytes32 salt) public {
    //     vm.prank(user);
    //     ConstructorRecorder recorder = new ConstructorRecorder{salt:salt}();
    //     assert(recorder.caller() == user);
    // }
}
