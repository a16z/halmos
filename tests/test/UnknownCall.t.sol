// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

import {IERC721TokenReceiver} from "forge-std/interfaces/IERC721.sol";

contract UnknownCallTest is Test {
    /// @custom:halmos --uninterpreted-unknown-calls=
    function check_unknown_not_allowed(address addr) public {
        // empty --uninterpreted-unknown-calls
        IERC721TokenReceiver(addr).onERC721Received(address(0), address(0), 0, ""); // expected to fail
    }

    function check_unknown_common_callbacks(address addr) public {
        // onERC721Received is included in the default --uninterpreted-unknown-calls
        IERC721TokenReceiver(addr).onERC721Received(address(0), address(0), 0, "");
    }

    function check_unknown_retsize_default(address addr) public {
        (bool success, bytes memory retdata) = addr.call(abi.encodeWithSelector(IERC721TokenReceiver.onERC721Received.selector, address(0), address(0), 0, ""));
        assert(retdata.length == 32); // default --return-size-of-unknown-calls=32
    }

    /// @custom:halmos --return-size-of-unknown-calls=64
    function check_unknown_retsize_64(address addr) public {
        (bool success, bytes memory retdata) = addr.call(abi.encodeWithSelector(IERC721TokenReceiver.onERC721Received.selector, address(0), address(0), 0, ""));
        assert(retdata.length == 64);
    }

    /// @custom:halmos --return-size-of-unknown-calls=0
    function check_unknown_retsize_0(address addr) public {
        (bool success, bytes memory retdata) = addr.call(abi.encodeWithSelector(IERC721TokenReceiver.onERC721Received.selector, address(0), address(0), 0, ""));
        assert(retdata.length == 0);
    }

    function check_unknown_call(address addr, uint amount, uint initial) public {
        vm.assume(addr != address(this));
        vm.deal(addr, 0);
        vm.deal(address(this), initial);

        (bool success, bytes memory retdata) = payable(addr).call{ value: amount }("");

        assert(retdata.length == 32); // default --return-size-of-unknown-calls=32

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
