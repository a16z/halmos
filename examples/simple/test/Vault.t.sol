// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";

import {Vault} from "../src/Vault.sol";

contract VaultMock is Vault {
    function setTotalAssets(uint _totalAssets) public {
        totalAssets = _totalAssets;
    }

    function setTotalShares(uint _totalShares) public {
        totalShares = _totalShares;
    }
}

/// @custom:halmos --solver-timeout-assertion 0
contract VaultTest is SymTest {
    VaultMock vault;

    function setUp() public {
        vault = new VaultMock();

        vault.setTotalAssets(svm.createUint256("A1"));
        vault.setTotalShares(svm.createUint256("S1"));
    }

    /// need to set a timeout for this test, the solver can run for hours
    /// @custom:halmos --solver-timeout-assertion 10000
    function check_deposit(uint assets) public {
        uint A1 = vault.totalAssets();
        uint S1 = vault.totalShares();

        vault.deposit(assets);

        uint A2 = vault.totalAssets();
        uint S2 = vault.totalShares();

        // assert(A1 / S1 <= A2 / S2);
        assert(A1 * S2 <= A2 * S1); // no counterexample
    }

    function check_mint(uint shares) public {
        uint A1 = vault.totalAssets();
        uint S1 = vault.totalShares();

        vault.mint(shares);

        uint A2 = vault.totalAssets();
        uint S2 = vault.totalShares();

        // assert(A1 / S1 <= A2 / S2);
        assert(A1 * S2 <= A2 * S1); // counterexamples exist
    }
}
