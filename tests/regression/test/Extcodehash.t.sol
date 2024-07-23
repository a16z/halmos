// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract A {}

contract B {
    // make sure bytecode is different from A
    function beep() public pure {}
}

contract Empty {
    // constructor returns 0-length runtime bytecode
    constructor() {
        assembly {
            return(0, 0)
        }
    }
}

contract ExtcodehashTest is Test, SymTest {
    address a1;
    bytes32 a1hash;

    function setUp() public {
        address _a1 = address(new A());
        bytes32 _a1hash;

        assembly {
            _a1hash := extcodehash(_a1)
        }

        a1 = _a1;
        a1hash = _a1hash;
    }

    function check_extcodehash_a1_eq_a2() external {
        address a2 = address(new A());
        bytes32 a2hash;
        assembly {
            a2hash := extcodehash(a2)
        }

        // extcodehash(a1) == extcodehash(a2)
        assertEq(a1hash, a2hash);
    }

    function check_extcodehash_a1_ne_b1() external {
        address b1 = address(new B());
        bytes32 b1hash;
        assembly {
            b1hash := extcodehash(b1)
        }

        // extcodehash(a1) != extcodehash(b1)
        assertNotEq(a1hash, b1hash);
    }

    function check_extcodehash_a1_eq_directHash() external {
        // extcodehash(a1) == keccak256(extcodecopy(a1))
        assertEq(a1hash, keccak256(a1.code));
    }

    function check_extcodehash_a1_eq_runtimeCodeHash() external {
        assertEq(a1hash, keccak256(type(A).runtimeCode));
    }

    function check_extcodehash_eq_directHash() external {
        uint256 thisCodeSize;
        assembly {
            thisCodeSize := codesize()
        }

        bytes memory thisCode = new bytes(thisCodeSize);
        bytes32 thisCodeHash;
        assembly {
            codecopy(add(thisCode, 0x20), 0, thisCodeSize)
            thisCodeHash := extcodehash(address())
        }

        // extcodehash(address()) == keccak256(codecopy())
        assertEq(thisCodeHash, keccak256(thisCode));
    }

    function check_extcodehash_empty() external {
        address emptyCodeAddr = address(new Empty());
        assertEq(emptyCodeAddr.code.length, 0, "Empty contract should have no code");

        bytes32 codehash;
        assembly {
            codehash := extcodehash(emptyCodeAddr)
        }

        assertEq(codehash, keccak256(""), "Expected codehash of the empty string");
    }

    /// yields a path where it is eq to 0, and a path where it is not
    /// so we expect a counterexample for this and also its negation
    function check_extcodehash_unknown_addr_eq_0() external {
        bytes32 codehash;
        assembly {
            codehash := extcodehash(0x1337)
        }

        assertEq(codehash, 0);
    }

    /// yields a path where it is eq to 0, and a path where it is not
    /// so we expect a counterexample for this and also its negation
    function check_extcodehash_unknown_addr_noteq_0()   external {
        bytes32 codehash;
        assembly {
            codehash := extcodehash(0x1337)
        }

        assertNotEq(codehash, 0);
    }

    function check_extcodehash_after_etch() external {
        address who = address(0x1337);
        bytes memory code = svm.createBytes(42, "code");
        vm.etch(who, code);

        bytes32 codehash;
        assembly {
            codehash := extcodehash(who)
        }

        assertEq(codehash, keccak256(code));
    }
}
