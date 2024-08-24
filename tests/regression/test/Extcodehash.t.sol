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

    function check_extcodehash_empty_contract() external {
        address emptyCodeAddr = address(new Empty());
        assertEq(emptyCodeAddr.code.length, 0, "Empty contract should have no code");

        bytes32 codehash;
        assembly {
            codehash := extcodehash(emptyCodeAddr)
        }

        assertEq(codehash, keccak256(""), "Expected codehash of the empty string");
    }

    function check_extcodehash_nonexisting_account() external {
        address nonExistingAcct = address(0x1337);
        assertEq(nonExistingAcct.code.length, 0, "Non-existing account should have no code");

        bytes32 codehash;
        assembly {
            codehash := extcodehash(nonExistingAcct)
        }

        // NOTE: extcodehash of non-existing account is 0, rather than keccak256(""), in the current evm implementation
        assertEq(codehash, 0, "Expected 0");
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

    function check_extcodehash_symbolic_address_empty(address a) external {
        address a2 = address(new Empty());

        vm.assume(a != address(this));
        vm.assume(a != a1);
        vm.assume(a != a2);

        bytes32 codehash;
        assembly {
            codehash := extcodehash(a)
        }

        assertEq(codehash, 0);
    }

    function check_extcodehash_symbolic_address_not_empty(address a) external {
        address a2 = address(new Empty());

        vm.assume(a == address(this) || a == a1 || a == a2);

        bytes32 codehash;
        assembly {
            codehash := extcodehash(a)
        }

        assertNotEq(codehash, 0);
    }

    /* TODO: improve symbolic keccak256 reasoning
    function check_extcodehash_symbolic_address_not_empty_2(address a) external {
        address a2 = address(new Empty());

        vm.assume(a == address(this) || a == a1);

        bytes32 codehash;
        assembly {
            codehash := extcodehash(a)
        }

        assertNotEq(codehash, keccak256(""));
    }
    */

    // backward-style test that combines the previous two tests
    function check_extcodehash_symbolic_address(address a) external {
        address a2 = address(new Empty());

        bytes32 codehash;
        assembly {
            codehash := extcodehash(a)
        }

        if (codehash == 0) {
            assert(a != address(this));
            assert(a != a1);
            assert(a != a2);
        } else {
            assert(a == address(this) || a == a1 || a == a2);
        }
    }

    function check_extcodesize_symbolic_address_empty(address a) external {
        address a2 = address(new Empty());

        vm.assume(a != address(this));
        vm.assume(a != a1);

        uint codesize_;
        assembly {
            codesize_ := extcodesize(a)
        }

        assertEq(codesize_, 0);
    }

    function check_extcodesize_symbolic_address_not_empty(address a) external {
        address a2 = address(new Empty());

        vm.assume(a == address(this) || a == a1);

        uint codesize_;
        assembly {
            codesize_ := extcodesize(a)
        }

        assertNotEq(codesize_, 0);
    }

    // backward-style test that combines the previous two tests
    function check_extcodesize_symbolic_address(address a) external {
        address a2 = address(new Empty());

        uint codesize_;
        assembly {
            codesize_ := extcodesize(a)
        }

        if (codesize_ == 0) {
            assert(a != address(this));
            assert(a != a1);
        } else {
            assert(a == address(this) || a == a1);
        }
    }

    function check_extcodesize_precompiles(address precompiled) external {
        vm.assume(1 <= uint160(precompiled));
        vm.assume(uint160(precompiled) <= 0xa);

        uint256 size;
        assembly {
            size := extcodesize(precompiled)
        }

        assertEq(size, 0);
    }

    function check_extcodehash_precompiles(address precompiled) external {
        vm.assume(1 <= uint160(precompiled));
        vm.assume(uint160(precompiled) <= 0xa);

        uint256 codehash;
        assembly {
            codehash := extcodehash(precompiled)
        }

        assertEq(codehash, 0);
    }

    function check_extcodesize_cheatcode() external {
        assertEq(VM_ADDRESS, address(0x7109709ECfa91a80626fF3989D68f67F5b1DD12D));
        assertEq(console.CONSOLE_ADDRESS, address(0x000000000000000000636F6e736F6c652e6c6f67));
        assertEq(SymTest.SVM_ADDRESS, address(0xF3993A62377BCd56AE39D773740A5390411E8BC9));

        assertEq(VM_ADDRESS.code.length, 1);
        assertEq(console.CONSOLE_ADDRESS.code.length, 0);
        assertEq(SymTest.SVM_ADDRESS.code.length, 1); // different from foundry
    }

    function check_extcodehash_cheatcode() external {
        assertEq(VM_ADDRESS.codehash, 0xb0450508e5a2349057c3b4c9c84524d62be4bb17e565dbe2df34725a26872291);
        assertEq(console.CONSOLE_ADDRESS.codehash, 0);
        assertEq(SymTest.SVM_ADDRESS.codehash, 0);
    }
}
