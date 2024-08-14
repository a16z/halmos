// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract Dummy { }

contract Target {
    Target public inner;
    address public caller;
    address public origin;

    function setInnerTarget(Target _inner) public {
        inner = _inner;
    }

    function reset() public {
        caller = address(0);
        origin = address(0);

        if (address(inner) != address(0)) {
            inner.reset();
        }
    }

    function recordCaller() public {
        caller = msg.sender;
        origin = tx.origin;

        if (address(inner) != address(0)) {
            inner.recordCaller();
        }
    }
}

contract ConstructorRecorder {
    address public caller;
    address public origin;

    constructor() {
        caller = msg.sender;
        origin = tx.origin;
    }
}

contract PrankyConstructor is TestBase {
    constructor(address user, address origin) {
        vm.startPrank(user, origin);
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
    Target inner;
    Ext ext;
    Dummy dummy;

    function setUp() public {
        target = new Target();
        inner = new Target();
        target.setInnerTarget(inner);
        ext = new Ext();
    }

    function prank(address user) public {
        vm.prank(user);
    }

    function checkNotPranked(Target _target, address realCaller) internal {
        assertEq(_target.caller(), realCaller);
        assertEq(_target.origin(), tx.origin);
    }

    function check_prank_single(address user) public {
        vm.prank(user);

        // the outer call is pranked
        target.recordCaller();
        assert(target.caller() == user);
        assert(target.origin() == tx.origin); // not pranked

        // but the inner call is not pranked
        checkNotPranked(inner, address(target));

        // check that the prank is no longer active
        target.recordCaller();
        checkNotPranked(target, address(this));
    }

    function check_prank_double(address user, address origin) public {
        vm.prank(user, origin);

        // the outer call is pranked
        target.recordCaller();
        assert(target.caller() == user);
        assert(target.origin() == origin);

        // the inner call also sees the pranked origin
        assert(inner.caller() == address(target));
        assert(target.origin() == origin);

        // check that the prank is no longer active
        target.recordCaller();
        checkNotPranked(target, address(this));
    }

    function check_startPrank_single(address user) public {
        vm.startPrank(user);

        // the outer call is pranked
        target.recordCaller();
        assert(target.caller() == user);
        assert(target.origin() == tx.origin); // not pranked

        // the inner call is not pranked
        checkNotPranked(inner, address(target));

        target.reset();
        assert(target.caller() == address(0));
        assert(target.origin() == address(0));
        assert(inner.caller() == address(0));
        assert(inner.origin() == address(0));

        // prank is still active until stopPrank() is called
        target.recordCaller();
        assert(target.caller() == user);
        assert(target.origin() == tx.origin); // not pranked
        checkNotPranked(inner, address(target));

        vm.stopPrank();

        // prank is no longer active
        target.recordCaller();
        checkNotPranked(target, address(this));
        checkNotPranked(inner, address(target));
    }

    function check_startPrank_double(address user, address origin) public {
        vm.startPrank(user, origin);

        target.recordCaller();
        assert(target.caller() == user);
        assert(target.origin() == origin);
        assert(inner.caller() == address(target)); // not pranked
        assert(inner.origin() == origin); // pranked

        target.reset();
        assert(target.caller() == address(0));
        assert(target.origin() == address(0));
        assert(inner.caller() == address(0));
        assert(inner.origin() == address(0));

        // prank is still active until stopPrank() is called
        target.recordCaller();
        assert(target.caller() == user);
        assert(target.origin() == origin);
        assert(inner.caller() == address(target)); // not pranked
        assert(inner.origin() == origin); // pranked

        vm.stopPrank();

        // prank is no longer active
        target.recordCaller();
        checkNotPranked(target, address(this));
        checkNotPranked(inner, address(target));
    }

    function check_prank_Internal(address user) public {
        prank(user); // indirect prank
        target.recordCaller();
        assert(target.caller() == user);
    }

    function check_prank_External(address user) public {
        ext.prank(user); // prank isn't propagated beyond the vm boundary
        target.recordCaller();
        assert(target.caller() == address(this));
    }

    function check_prank_ExternalSelf(address user) public {
        this.prank(user); // prank isn't propagated beyond the vm boundary
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

    function check_prank_Constructor(address user, address origin) public {
        address senderBefore = msg.sender;
        address originBefore = tx.origin;

        vm.prank(user, origin);
        ConstructorRecorder recorder = new ConstructorRecorder();
        assert(recorder.caller() == user);
        assert(recorder.origin() == origin);

        // origin and sender are restored
        assertEq(msg.sender, senderBefore);
        assertEq(tx.origin, originBefore);
    }

    function check_prank_ConstructorCreate2(address user, address origin, bytes32 salt) public {
        address senderBefore = msg.sender;
        address originBefore = tx.origin;

        vm.prank(user, origin);
        ConstructorRecorder recorder = new ConstructorRecorder{salt:salt}();
        assert(recorder.caller() == user);
        assert(recorder.origin() == origin);

        // origin and sender are restored
        assertEq(msg.sender, senderBefore);
        assertEq(tx.origin, originBefore);
    }

    function check_prank_startPrank_in_constructor(address user, address origin) public {
        address senderBefore = msg.sender;
        address originBefore = tx.origin;

        PrankyConstructor pranky = new PrankyConstructor(user, origin);

        // results are not affected by the startPrank in the constructor
        assertEq(msg.sender, senderBefore);
        assertEq(tx.origin, originBefore);

        target.recordCaller();
        assert(target.caller() == address(this));
        assert(target.origin() == originBefore);
    }
}
