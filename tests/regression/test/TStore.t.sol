// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract C {
    uint public slot0;

    function sstore(uint slot, uint value) public {
        assembly {
            sstore(slot, value)
        }
    }

    function sload(uint slot) public returns (uint value) {
        assembly {
            value := sload(slot)
        }
    }

    function tstore(uint slot, uint value) public {
        assembly {
            tstore(slot, value)
        }
    }

    function tload(uint slot) public returns (uint value) {
        assembly {
            value := tload(slot)
        }
    }
}

/// @custom:halmos --storage-layout generic
contract TStoreTest is Test {
    C c;

    function setUp() public {
        c = new C();
    }

    function check_sload() public {
        assertEq(c.sload(0), 0);
    }

    function check_tload() public {
        assertEq(c.tload(0), 0);
    }

    function check_sstore(uint x) public {
        c.sstore(0, x);
        assertEq(c.sload(0), x);
        assertEq(c.slot0(), x);

        // transient storage isn't affected
        assertEq(c.tload(0), 0);
    }

    function check_tstore(uint x) public {
        c.tstore(0, x);
        assertEq(c.tload(0), x);

        // persistent storage isn't affected
        assertEq(c.slot0(), 0);
        assertEq(c.sload(0), 0);
    }

    function invariant_storage() public {
        assertEq(c.sload(0), 0); // fail
    }

    function invariant_transient_storage() public {
        // note: transient storage is reset after each tx in the invariant tx sequence
        assertEq(c.tload(0), 0); // pass
    }
}
