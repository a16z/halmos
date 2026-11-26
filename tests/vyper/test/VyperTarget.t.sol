// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {Test} from "forge-std/Test.sol";

interface ICounter {
    function count() external view returns (uint256);
    function add(uint256) external;
}

interface IVault {
    function deposit(uint256) external;
    function withdraw(uint256) external;
    function balanceOf(address) external view returns (uint256);
    function total() external view returns (uint256);
    function boom(uint256) external;
}

interface IImmutable {
    function LIMIT() external view returns (uint256);
    function under(uint256) external view returns (bool);
}

/// @notice solidity tests for vyper contracts
contract VyperTargetTest is Test {
    ICounter counter;
    IVault vault;
    IImmutable imm;

    function setUp() public {
        // all supported getCode path formats
        counter = ICounter(deployCode("Counter.vy:Counter"));
        vault = IVault(deployCode("src/Vault.vy"));
        imm = IImmutable(deployCode("Immutable.vy", abi.encode(uint256(100))));
    }

    function check_counter(uint256 x) public {
        // expected to fail (x == 13)
        uint256 before = counter.count();
        counter.add(x);
        assertEq(counter.count(), before + x);
    }

    function check_hashmap(address a, address b, uint256 x, uint256 y) public {
        // exercises vyper's HashMap layout, keccak256(slot . key)
        vm.assume(a != b);
        vm.prank(a);
        vault.deposit(x);
        vm.prank(b);
        vault.deposit(y);
        assertEq(vault.balanceOf(a), x);
        assertEq(vault.balanceOf(b), y);
        assertEq(vault.total(), x + y);
    }

    function check_unreachable_in_target(uint256 x) public {
        // expected to fail (x == 42): INVALID in the target bubbles up as an empty revert
        vault.boom(x);
    }

    function check_unreachable_caught(uint256 x) public {
        // the failure is caught, so it must not be reported
        try vault.boom(x) {} catch {}
    }

    function check_immutable(uint256 x) public view {
        assertEq(imm.LIMIT(), 100);
        assertEq(imm.under(x), x <= 100);
    }
}
