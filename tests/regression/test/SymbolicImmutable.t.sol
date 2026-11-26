// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

/// @notice a symbolic immutable patched into the code with a read-modify-write of a
///         32-byte word, as solar does for an address immutable held in a PUSH20
/// @dev see upstream halmos issue #608
contract SymbolicImmutableTest is Test {
    address owner;
    address target;

    // 0x00 PUSH20 <owner>  0x15 CALLER  0x16 EQ  0x17 PUSH1 0x1d  0x19 JUMPI
    // 0x1a PUSH0 PUSH0 REVERT
    // 0x1d JUMPDEST PUSH1 1 PUSH0 MSTORE PUSH1 0x20 PUSH0 RETURN
    bytes constant RUNTIME =
        hex"7300000000000000000000000000000000000000003314601d57" hex"5f5ffd" hex"5b60015f5260205ff3";

    // returns the code that follows
    bytes constant INIT = hex"600b5981380380925939f3";

    function deploy(address immutableValue) internal returns (address addr) {
        bytes memory runtime = RUNTIME;
        assembly {
            // the word holds the 20 bytes of the immutable, then 12 bytes of code
            let p := add(runtime, 33)
            mstore(p, or(and(mload(p), 0xffffffffffffffffffffffff), shl(96, immutableValue)))
        }
        bytes memory initcode = abi.encodePacked(INIT, runtime);
        assembly {
            addr := create(0, add(initcode, 32), mload(initcode))
        }
        require(addr != address(0), "deployment failed");
    }

    function setUp() public {
        owner = vm.addr(1); // symbolic in dolmos
        target = deploy(owner);
    }

    function check_jump_after_symbolic_immutable() public {
        vm.prank(owner);
        (bool success, bytes memory ret) = target.call("");
        assertTrue(success);
        assertEq(abi.decode(ret, (uint256)), 1);
    }

    function check_other_caller_reverts(address caller) public {
        vm.assume(caller != owner);
        vm.prank(caller);
        (bool success,) = target.call("");
        assertFalse(success);
    }

    function check_concrete_immutable() public {
        address t = deploy(address(0x1234));
        vm.prank(address(0x1234));
        (bool success,) = t.call("");
        assertTrue(success);
    }
}
