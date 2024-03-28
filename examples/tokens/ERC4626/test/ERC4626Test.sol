// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Test} from "forge-std/Test.sol";

import {IERC4626} from "forge-std/interfaces/IERC4626.sol";

abstract contract ERC4626Test is SymTest, Test {
    // erc4626 vault address
    address internal vault;

    // vault share holders
    address[] internal holders;

    function setUp() public virtual;

    function check_RT_deposit_redeem(uint assets) public virtual {
        address caller = holders[0];
        vm.prank(caller); uint shares = IERC4626(vault).deposit(assets, caller);
        vm.prank(caller); uint assets2 = IERC4626(vault).redeem(shares, caller, caller);
        assert(assets2 <= assets);
    }

    function check_RT_mint_withdraw(uint shares) public virtual {
        address caller = holders[0];
        vm.prank(caller); uint assets = IERC4626(vault).mint(shares, caller);
        vm.prank(caller); uint shares2 = IERC4626(vault).withdraw(assets, caller, caller);
        assert(shares2 >= shares);
    }
}
