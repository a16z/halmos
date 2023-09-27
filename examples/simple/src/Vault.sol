// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract Vault {
    uint public totalAssets;
    uint public totalShares;

    function deposit(uint assets) public returns (uint shares) {
        shares = (assets * totalShares) / totalAssets;

        totalAssets += assets;
        totalShares += shares;
    }

    function mint(uint shares) public returns (uint assets) {
        assets = (shares * totalAssets) / totalShares; // buggy

        totalAssets += assets;
        totalShares += shares;
    }
}
