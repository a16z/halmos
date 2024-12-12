// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract C {
    uint num;

    receive() external payable {}

    function set(uint val) public {
        num = val;
    }
}

contract SnapshotTest is SymTest, Test {
    C c;

    function setUp() public {
        c = new C();
    }

    function check_snapshot() public {
        uint storage0 = svm.snapshotStorage(address(c));
        uint state0 = vm.snapshotState();
        console.log(storage0);
        console.log(state0);

        c.set(0);

        uint storage1 = svm.snapshotStorage(address(c));
        uint state1 = vm.snapshotState();
        console.log(storage1);
        console.log(state1);

        // NOTE: two storages are semantically equal, but not structually equal
        // assertEq(storage0, storage1);
        // assertEq(state0, state1);

        c.set(0);

        uint storage2 = svm.snapshotStorage(address(c));
        uint state2 = vm.snapshotState();
        console.log(storage2);
        console.log(state2);

        assertEq(storage1, storage2);
        assertEq(state1, state2);

        c.set(1);

        uint storage3 = svm.snapshotStorage(address(c));
        uint state3 = vm.snapshotState();
        console.log(storage3);
        console.log(state3);

        assertNotEq(storage2, storage3);
        assertNotEq(state2, state3);

        c.set(0);

        uint storage4 = svm.snapshotStorage(address(c));
        uint state4 = vm.snapshotState();
        console.log(storage4);
        console.log(state4);

        assertEq(storage2, storage4);
        assertEq(state2, state4);
    }

    function check_this_balance_snapshot() public {
        vm.deal(address(this), 10);

        uint state0 = vm.snapshotState();
        console.log(state0);

        payable(c).transfer(1);

        uint state1 = vm.snapshotState();
        console.log(state1);

        assertNotEq(state0, state1);

        payable(c).transfer(0);

        uint state2 = vm.snapshotState();
        console.log(state2);

        assertEq(state1, state2);
    }

    function check_this_storage_snapshot() public {
        uint state0 = vm.snapshotState();
        uint storage0 = svm.snapshotStorage(address(this));
        uint storage0_c = svm.snapshotStorage(address(c));
        console.log(state0);
        console.log(storage0);
        console.log(storage0_c);

        address old_c = address(c);

        c = C(payable(0));

        uint state1 = vm.snapshotState();
        uint storage1 = svm.snapshotStorage(address(this));
        uint storage1_c = svm.snapshotStorage(old_c);
        console.log(state1);
        console.log(storage1);
        console.log(storage1_c);

        assertNotEq(state0, state1);
        assertNotEq(storage0, storage1); // global variable updated
        assertEq(storage0_c, storage1_c); // existing account preserved
    }

    function check_new_account_snapshot() public {
        uint state0 = vm.snapshotState();
        console.log(state0);

        C tmp = new C();

        uint state1 = vm.snapshotState();
        console.log(state1);

        assertNotEq(state0, state1); // new account in state1
    }

    function check_balance_snapshot() public {
        vm.deal(address(c), 10);

        uint state0 = vm.snapshotState();
        console.log(state0);

        vm.deal(address(c), 10);

        uint state1 = vm.snapshotState();
        console.log(state1);

        // NOTE: symbolic balance mappings are not structurally equal
        // assertEq(state0, state1);
    }
}
