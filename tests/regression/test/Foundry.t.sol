// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "forge-std/StdCheats.sol";

import "../src/Counter.sol";

contract DeepFailer is Test {
    function do_test(uint256 x) external {
        if (x >= 6) {
            fail();
        } else {
            (bool success, ) = address(this).call(abi.encodeWithSelector(this.do_test.selector, x + 1));
            success; // silence warnings
        }
    }

    function check_fail_cheatcode() public {
        DeepFailer(address(this)).do_test(0);
    }
}

contract EarlyFailTest is Test {
    function do_fail() external {
        fail();
    }

    function check_early_fail_cheatcode(uint x) public {
        // we want `fail()` to happen in a nested context,
        // to test that it ends not just the current context but the whole run
        address(this).call(abi.encodeWithSelector(this.do_fail.selector, ""));

        // this shouldn't be reached due to the early fail() semantics.
        // if this assertion is executed, two counterexamples will be generated:
        // - counterexample caused by fail(): x > 0
        // - counterexample caused by assert(x > 0): x == 0
        assert(x > 0);
    }

    function check_failed_cheatcode() public {
        // since fail() halts immediately, failed() always returns true here
        assertFalse(failed());
    }
}

contract FoundryTest is Test {
    /* TODO: support checkFail prefix
    function checkFail() public {
        assertTrue(false);
    }
    */

    function check_caller() public {
        assertEq(msg.sender, address(0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38));
    }

    function check_origin() public {
        assertEq(tx.origin, address(0x1804c8AB1F12E6bbf3894d4083f33e07309d1f38));
    }

    function check_this() public {
        assertEq(address(this), address(0x7FA9385bE102ac3EAc297483Dd6233D62b3e1496));
    }

    function check_assume(uint x) public {
        vm.assume(x < 10);
        assertLt(x, 100);
    }

    function check_deployCode(uint x) public {
        Counter counter = Counter(deployCode("./out/Counter.sol/Counter.json"));
        counter.set(x);
        assertEq(counter.cnt(), x);

        Counter counter2 = Counter(deployCode("Counter.sol:Counter"));
        counter2.set(x);
        assertEq(counter2.cnt(), x);
    }

    function check_etch_Concrete() public {
        vm.etch(address(0x42), hex"60425f526001601ff3");
        (bool success, bytes memory retval) = address(0x42).call("");

        assertTrue(success);
        assertEq(retval.length, 1);
        assertEq(uint256(uint8(retval[0])), 0x42);
    }

    function check_etch_Overwrite() public {
        vm.etch(address(0x42), hex"60425f526001601ff3");
        (, bytes memory retval) = address(0x42).call("");

        assertEq(retval.length, 1);
        assertEq(uint256(uint8(retval[0])), 0x42);

        vm.etch(address(0x42), hex"60AA5f526001601ff3");
        (, retval) = address(0x42).call("");

        assertEq(retval.length, 1);
        assertEq(uint256(uint8(retval[0])), 0xAA);
    }

    function check_etch_emptyBytecode() public {
        vm.etch(address(0x42), hex"");
        (bool success, ) = address(0x42).call("");

        assertTrue(success);
    }

    /// @notice etching to a symbolic address is not supported
    // function check_etch_SymbolicAddr(address who) public {
    //     vm.etch(who, hex"60425f526001601ff3");
    //     (bool success, bytes memory retval) = who.call("");

    //     assertTrue(success);
    //     assertEq(retval.length, 1);
    //     assertEq(uint256(uint8(retval[0])), 0x42);
    // }

    /// @notice etching symbolic code is not supported
    // function check_etch_FullSymbolic(address who, bytes memory code) public {
    //     vm.etch(who, code);
    //     assertEq(code, who.code);
    // }

    function check_assertEqCall(uint256 a, uint256 b) public {
        assertEqCall(
            address(this), abi.encodeCall(this._add, (a, b)), abi.encodeCall(this._add, (a, b))
        );
    }

    function _add(uint256 a, uint256 b) public pure returns (uint256 c) {
        c = a + b;
    }
}


contract NotEtchFriendly {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function beepBoop() public {
        console2.log("owner is", owner);
        require(msg.sender == owner, "NotEtchFriendly: only owner can beep boop");
    }
}

contract TestNotEtchFriendly is Test {
    NotEtchFriendly target;

    function setUp() public {
        /// @dev this is supported in foundry, but not halmos (can't vm.store to uninitialized account)
        // make address(this) the owner of the yet-to-be-deployed contract
        // vm.store(address(42), 0, bytes32(uint256(uint160(address(this)))));

        // etch does not run the constructor, so owner is not set by the constructor
        // additionally, vm.etch does not reset storage (unlike CREATE2)
        vm.etch(address(42), type(NotEtchFriendly).runtimeCode);

        target = NotEtchFriendly(address(42));
    }

    function check_etch_no_owner(address sender) external {
        vm.prank(sender);
        target.beepBoop();

        assertEq(sender, address(0));
    }

    function check_etch_then_store() external {
        // make address(this) the owner of the contract, emulating the constructor that did not run
        vm.store(address(42), 0, bytes32(uint256(uint160(address(this)))));

        target.beepBoop();
    }

    function check_etch_then_load() external {
        assertEq(target.owner(), address(0));
    }
}
