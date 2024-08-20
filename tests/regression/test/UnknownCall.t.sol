// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

import {IERC721TokenReceiver} from "forge-std/interfaces/IERC721.sol";

contract UnknownCallTest is Test {
    function check_unknown_retsize_0(address addr) public {
        (bool success, bytes memory retdata) = addr.call(abi.encodeWithSelector(IERC721TokenReceiver.onERC721Received.selector, address(0), address(0), 0, ""));
        if (success) {
            // if addr is not this, then addr is nonexisting thus the call to addr will immediately succeed with empty returndata
            assertNotEq(addr, address(this));
            assertEq(retdata.length, 0);
        } else {
            // if addr is equal to this, then the call to onERC721Received will fail since it is not implemented in this contract
            assertEq(addr, address(this));
            assertEq(retdata.length, 0); // the default fallback reverts with empty returndata
        }
    }

    function check_unknown_call(address addr, uint amount, uint initial) public {
        vm.assume(addr != address(this));
        vm.deal(addr, 0);
        vm.deal(address(this), initial);

        (bool success, bytes memory retdata) = payable(addr).call{ value: amount }("");

        assert(retdata.length == 0); // the returndata of a nonexisting contract call is always empty, even if it fails due to insufficient balance

        if (success) {
            assert(initial >= amount);
            assert(addr.balance == amount);
            assert(address(this).balance == initial - amount);
        } else {
            assert(addr.balance == 0);
            assert(address(this).balance == initial);
        }
    }

    function check_unknown_send(address addr, uint amount, uint initial) public {
        vm.assume(addr != address(this));
        vm.deal(addr, 0);
        vm.deal(address(this), initial);

        bool success = payable(addr).send(amount);

        if (success) {
            assert(initial >= amount);
            assert(addr.balance == amount);
            assert(address(this).balance == initial - amount);
        } else {
            // NOTE: currently this branch is not reachable, because the balance is implicitly assumed to be enough
            // TODO: fix halmos to consider the case where the balance is not enough
            assert(false);
            assert(addr.balance == 0);
            assert(address(this).balance == initial);
        }
    }

    function check_unknown_send_fail(address addr) public {
        vm.assume(addr != address(this));
        vm.deal(addr, 0);
        vm.deal(address(this), 1);

        bool success = payable(addr).send(2); // get stuck

        assert(!success);
    }

    function check_unknown_transfer(address addr, uint amount, uint initial) public {
        vm.assume(addr != address(this));
        vm.deal(addr, 0);
        vm.deal(address(this), initial);

        payable(addr).transfer(amount); // revert if fail

        // at this point, transfer succeeds because it reverts on failure
        assert(initial >= amount);
        assert(addr.balance == amount);
        assert(address(this).balance == initial - amount);
    }
}
