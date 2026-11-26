// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

// SELFDESTRUCT with the EIP-6780 semantics (a16z/halmos#411)

contract Destructible {
    uint256 public x = 1;

    constructor() payable {}

    function destroy(address payable beneficiary) external {
        selfdestruct(beneficiary);
    }

    function destroyThenRevert(address payable beneficiary) external {
        this.destroy(beneficiary);
        revert("undo");
    }

    receive() external payable {}
}

contract DestroyInConstructor {
    constructor(address payable beneficiary) payable {
        selfdestruct(beneficiary);
    }
}

contract SelfDestructTest is Test {
    Destructible preexisting; // created in setUp, i.e. in a previous transaction
    address payable constant BENEFICIARY = payable(address(0xbeef));

    function setUp() public {
        preexisting = new Destructible{value: 1 ether}();
    }

    // not created in the current transaction: only the balance is transferred
    function check_preexisting_keeps_code_and_storage() public {
        uint256 before = BENEFICIARY.balance;
        preexisting.destroy(BENEFICIARY);

        assertEq(address(preexisting).balance, 0);
        assertEq(BENEFICIARY.balance, before + 1 ether);
        assertGt(address(preexisting).code.length, 0);
        assertEq(preexisting.x(), 1);
    }

    // the frame halts: code after selfdestruct is not executed, and the call succeeds
    function check_halts_successfully() public {
        (bool success, bytes memory ret) =
            address(preexisting).call(abi.encodeCall(Destructible.destroy, (BENEFICIARY)));
        assertTrue(success);
        assertEq(ret.length, 0);
    }

    // sending the balance to itself is a no-op for a preexisting account
    function check_preexisting_self_beneficiary() public {
        preexisting.destroy(payable(address(preexisting)));
        assertEq(address(preexisting).balance, 1 ether);
    }

    // created in the current transaction: the account is deleted at the end of the transaction,
    // so it is still alive until then
    function check_created_in_tx_alive_until_end_of_tx() public {
        Destructible d = new Destructible{value: 2 ether}();
        d.destroy(BENEFICIARY);

        assertEq(address(d).balance, 0);
        assertEq(BENEFICIARY.balance, 2 ether);
        assertGt(address(d).code.length, 0);
        assertEq(d.x(), 1);
    }

    // selfdestruct in the constructor: the value is forwarded, and the address still has code
    // until the end of the transaction
    function check_destroy_in_constructor() public {
        address a = address(new DestroyInConstructor{value: 3 ether}(BENEFICIARY));
        assertEq(a.balance, 0);
        assertEq(BENEFICIARY.balance, 3 ether);
    }

    // a reverted selfdestruct has no effect
    function check_reverted_selfdestruct() public {
        try preexisting.destroyThenRevert(BENEFICIARY) {
            assert(false);
        } catch {}
        assertEq(address(preexisting).balance, 1 ether);
        assertEq(BENEFICIARY.balance, 0);
    }

    // symbolic beneficiary
    function check_symbolic_beneficiary(address payable to) public {
        vm.assume(to != address(preexisting));
        uint256 before = to.balance;
        vm.assume(before <= 100 ether);
        preexisting.destroy(to);
        assertEq(to.balance, before + 1 ether);
    }

    // expected failure: sanity check that assertions on the transfer are meaningful
    function check_balance_moved_fail() public {
        preexisting.destroy(BENEFICIARY);
        assertEq(address(preexisting).balance, 1 ether);
    }
}

// accounts created and self-destructed in the same transaction (here, setUp) are deleted
// at the end of that transaction (EIP-6780)
contract SelfDestructDeletedTest is Test {
    Destructible d;
    Destructible kept;
    address payable constant BENEFICIARY = payable(address(0xbeef));

    function setUp() public {
        d = new Destructible{value: 1 ether}();
        d.destroy(BENEFICIARY);
        kept = new Destructible();
    }

    function check_deleted_after_tx() public view {
        assertEq(address(d).code.length, 0);
        assertEq(address(d).balance, 0);
        assertEq(BENEFICIARY.balance, 1 ether);
        assertGt(address(kept).code.length, 0);
    }

    function check_call_to_deleted_account() public {
        (bool success, bytes memory ret) = address(d).call(abi.encodeWithSignature("x()"));
        assertTrue(success); // call to an account without code succeeds
        assertEq(ret.length, 0);
    }
}

// before Cancun, SELFDESTRUCT deletes the account at the end of the transaction,
// even if it was not created in that transaction (a16z/halmos#128)
/// @custom:dolmos --evm-version shanghai
contract SelfDestructShanghaiTest {
    Destructible preexisting;
    address payable constant BENEFICIARY = payable(address(0xbeef));

    function setUp() public {
        preexisting = new Destructible{value: 1 ether}();
    }

    // still alive until the end of the transaction
    function check_preexisting_alive_until_end_of_tx() public {
        preexisting.destroy(BENEFICIARY);
        assert(address(preexisting).balance == 0);
        assert(BENEFICIARY.balance == 1 ether);
        assert(address(preexisting).code.length > 0);
    }
}

/// @custom:dolmos --evm-version shanghai
contract SelfDestructShanghaiDeletedTest {
    Destructible preexisting;

    // the account is created in the constructor (first transaction), and destroyed in setUp
    constructor() {
        preexisting = new Destructible();
    }

    function setUp() public {
        preexisting.destroy(payable(address(0xbeef)));
    }

    function check_preexisting_deleted_after_tx() public view {
        assert(address(preexisting).code.length == 0);
    }
}
