// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract Target {
    error Unauthorized(address who);
    error Plain();

    event Deposit(address indexed from, uint256 indexed id, uint256 amount);
    event Other(uint256 x);
    event Anon(uint256 indexed a, uint256 b) anonymous;

    uint256 public total;

    function requireLt(uint256 x, uint256 bound) external pure returns (uint256) {
        require(x < bound, "too big");
        return x;
    }

    function onlyOwner(address caller) external pure {
        if (caller != address(0xbeef)) revert Unauthorized(caller);
    }

    function plain(bool fail) external pure {
        if (fail) revert Plain();
    }

    function ok() external pure returns (uint256) {
        return 42;
    }

    function deposit(uint256 id, uint256 amount) external {
        total += amount;
        emit Other(amount);
        emit Deposit(msg.sender, id, amount);
    }

    function anon(uint256 a, uint256 b) external {
        emit Anon(a, b);
    }

    function depositTwice(uint256 amount) external {
        emit Other(amount);
        emit Other(amount);
    }
}

contract Inner {
    function boom() external pure {
        revert("inner");
    }
}

contract Outer {
    Inner public inner = new Inner();

    function callInner() external view {
        inner.boom();
    }
}

contract Reverting {
    constructor(bool fail) {
        require(!fail, "ctor");
    }
}

/// @dev overloads with a count, missing from the pinned forge-std
interface VmCount {
    function expectRevert(uint64 count) external;
    function expectRevert(bytes4 revertData, uint64 count) external;
    function expectEmit(uint64 count) external;
}

/// @dev regression tests for halmos issue #409: vm.expectRevert / vm.expectEmit
contract ExpectTest is Test {
    Target target;
    Outer outer;
    VmCount vmc = VmCount(address(vm));

    event Deposit(address indexed from, uint256 indexed id, uint256 amount);
    event Other(uint256 x);
    event Anon(uint256 indexed a, uint256 b) anonymous;

    function setUp() public {
        target = new Target();
        outer = new Outer();
    }

    //
    // expectRevert
    //

    function check_expectRevert_any(uint256 x) public {
        vm.assume(x >= 10);
        vm.expectRevert();
        target.requireLt(x, 10);
    }

    function check_expectRevert_any_fail(uint256 x) public {
        // fails for x < 10
        vm.expectRevert();
        target.requireLt(x, 10);
    }

    function check_expectRevert_string(uint256 x) public {
        vm.assume(x >= 10);
        vm.expectRevert("too big");
        target.requireLt(x, 10);
    }

    function check_expectRevert_string_bytes(uint256 x) public {
        vm.assume(x >= 10);
        vm.expectRevert(abi.encodeWithSignature("Error(string)", "too big"));
        target.requireLt(x, 10);
    }

    function check_expectRevert_wrong_string_fail(uint256 x) public {
        vm.assume(x >= 10);
        vm.expectRevert("wrong message");
        target.requireLt(x, 10);
    }

    function check_expectRevert_custom_error(address who) public {
        vm.assume(who != address(0xbeef));
        vm.expectRevert(abi.encodeWithSelector(Target.Unauthorized.selector, who));
        target.onlyOwner(who);
    }

    function check_expectRevert_custom_error_symbolic_fail(address who, address expected) public {
        // fails when who != expected
        vm.assume(who != address(0xbeef));
        vm.expectRevert(abi.encodeWithSelector(Target.Unauthorized.selector, expected));
        target.onlyOwner(who);
    }

    function check_expectRevert_selector() public {
        vm.expectRevert(Target.Plain.selector);
        target.plain(true);
    }

    function check_expectRevert_selector_with_args_fail(address who) public {
        // the full revert data is compared: the arguments are missing
        vm.assume(who != address(0xbeef));
        vm.expectRevert(Target.Unauthorized.selector);
        target.onlyOwner(who);
    }

    function check_expectPartialRevert(address who) public {
        vm.assume(who != address(0xbeef));
        vm.expectPartialRevert(Target.Unauthorized.selector);
        target.onlyOwner(who);
    }

    function check_expectRevert_no_revert_fail() public {
        vm.expectRevert();
        target.plain(false);
    }

    function check_expectRevert_returns_success() public {
        // the call is reported as successful to the caller
        vm.expectRevert();
        (bool success,) = address(target).call(abi.encodeCall(Target.plain, (true)));
        assertTrue(success);
    }

    function check_expectRevert_state_is_reverted(uint256 amount) public {
        uint256 before = target.total();
        vm.expectRevert();
        this.depositAndRevert(amount);
        assertEq(target.total(), before);
    }

    function depositAndRevert(uint256 amount) external {
        target.deposit(1, amount);
        revert("rollback");
    }

    function check_expectRevert_with_prank() public {
        // cheatcode calls in between don't consume the expectation
        vm.expectRevert(abi.encodeWithSelector(Target.Unauthorized.selector, address(this)));
        vm.prank(address(0x1234));
        target.onlyOwner(address(this));
    }

    function check_expectRevert_reverter() public {
        vm.expectRevert("inner", address(outer.inner()));
        outer.callInner();
    }

    function check_expectRevert_reverter_fail() public {
        vm.expectRevert(address(outer));
        outer.callInner();
    }

    function check_expectRevert_count() public {
        vmc.expectRevert(Target.Plain.selector, 2);
        target.plain(true);
        target.plain(true);
    }

    function check_expectRevert_count_fail() public {
        vmc.expectRevert(Target.Plain.selector, 2);
        target.plain(true);
        target.plain(false);
    }

    function check_expectRevert_count_zero() public {
        vmc.expectRevert(0);
        target.plain(false);
    }

    function check_expectRevert_count_zero_fail() public {
        vmc.expectRevert(0);
        target.plain(true);
    }

    function check_expectRevert_create() public {
        vm.expectRevert(bytes("ctor"));
        new Reverting(true);
    }

    function check_expectRevert_pending_fail() public {
        // the expected call never happens
        vm.expectRevert();
    }

    //
    // expectEmit
    //

    function check_expectEmit(uint256 id, uint256 amount) public {
        vm.expectEmit();
        emit Deposit(address(this), id, amount);
        target.deposit(id, amount);
    }

    function check_expectEmit_wrong_data_fail(uint256 id, uint256 amount, uint256 other) public {
        // fails when other != amount
        vm.expectEmit();
        emit Deposit(address(this), id, other);
        target.deposit(id, amount);
    }

    function check_expectEmit_skip_data(uint256 id, uint256 amount, uint256 other) public {
        vm.expectEmit(true, true, false, false);
        emit Deposit(address(this), id, other);
        target.deposit(id, amount);
    }

    function check_expectEmit_wrong_topic_fail(uint256 id, uint256 amount) public {
        vm.expectEmit(true, false, false, true);
        emit Deposit(address(0xdead), id, amount);
        target.deposit(id, amount);
    }

    function check_expectEmit_emitter(uint256 id, uint256 amount) public {
        vm.expectEmit(address(target));
        emit Deposit(address(this), id, amount);
        target.deposit(id, amount);
    }

    function check_expectEmit_wrong_emitter_fail(uint256 id, uint256 amount) public {
        vm.expectEmit(address(outer));
        emit Deposit(address(this), id, amount);
        target.deposit(id, amount);
    }

    function check_expectEmit_ordered(uint256 id, uint256 amount) public {
        vm.expectEmit();
        emit Other(amount);
        vm.expectEmit();
        emit Deposit(address(this), id, amount);
        target.deposit(id, amount);
    }

    function check_expectEmit_wrong_order_fail(uint256 id, uint256 amount) public {
        vm.expectEmit();
        emit Deposit(address(this), id, amount);
        vm.expectEmit();
        emit Other(amount);
        target.deposit(id, amount);
    }

    function check_expectEmit_anonymous(uint256 a, uint256 b) public {
        vm.expectEmitAnonymous();
        emit Anon(a, b);
        target.anon(a, b);
    }

    function check_expectEmit_count(uint256 amount) public {
        vmc.expectEmit(2);
        emit Other(amount);
        target.depositTwice(amount);
    }

    function check_expectEmit_count_fail(uint256 amount) public {
        vmc.expectEmit(1);
        emit Other(amount);
        target.depositTwice(amount);
    }

    function check_expectEmit_no_emit_fail(uint256 id, uint256 amount) public {
        // the expected event is not emitted before the call
        vm.expectEmit();
        target.deposit(id, amount);
    }

    function check_expectEmit_pending_fail(uint256 id, uint256 amount) public {
        // the expected call never happens
        vm.expectEmit();
        emit Deposit(address(this), id, amount);
    }
}
