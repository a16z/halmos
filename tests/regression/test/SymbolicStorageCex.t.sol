// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract StorageCexVault {
    uint256 public total;
    address public admin;
    mapping(address => uint256) public balanceOf;

    function increment() public {
        total++;
    }
}

/// @notice the counterexamples of these tests are values of the symbolic storage
/// @dev see upstream halmos issue #577
contract SymbolicStorageCexTest is Test, SymTest {
    StorageCexVault vault;

    function setUp() public {
        vault = new StorageCexVault();
        svm.enableSymbolicStorage(address(vault));
    }

    // the example of the issue
    function check_storage_cex_increment() public {
        vm.assume(vault.total() != 2);
        vault.increment();
        assert(vault.total() != 2);
    }

    function check_storage_cex_scalar() public view {
        assert(vault.admin() != address(0xbeef));
    }

    function check_storage_cex_mapping() public view {
        assert(vault.balanceOf(address(0x1234)) != 77);
    }
}

/// @notice the storage of this vault is not symbolic: no storage value is reported
contract ConcreteStorageCexTest is Test {
    StorageCexVault vault;

    function setUp() public {
        vault = new StorageCexVault();
    }

    function check_storage_cex_concrete(address a) public view {
        assert(vault.balanceOf(a) != 0);
    }
}
