// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

// inspired by https://github.com/aviggiano/halmos-stateful-erc20

import {ERC20} from "../src/ERC20.sol";
import {Test} from "forge-std/Test.sol";

/// @custom:halmos --solver bitwuzla-abs --loop 3 --solver-timeout-assertion 0
contract ERC20Test is Test {
    // token address
    ERC20 internal token;

    // token holders
    address[] internal holders;

    function setUp() public virtual {
        // deploy token
        token = new ERC20("ERC20", "ERC20");

        // declare token holders
        holders = new address[](3);
        holders[0] = address(0x1001);
        holders[1] = address(0x1002);
        holders[2] = address(0x1003);

        // setup initial balances
        for (uint i = 0; i < holders.length; i++) {
            token.mint(holders[i], 1_000_000e18);
        }

        // register this contract as the target to call the handler functions
        targetContract(address(this));
    }

    /*
     * handlers
     *
     * handlers are used to track token holders, allowing us to iterate over
     * them when calculating the sum of balances for specifying invariants.
     * for simplicity, in this example, only the initial token holders are
     * allowed as recipients of tokens.
     */

    function transfer(address to, uint256 amount) public asCaller assumeHolder(to) returns (bool) {
        return token.transfer(to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) public asCaller assumeHolder(to) returns (bool) {
        return token.transferFrom(from, to, amount);
    }

    function mint(address to, uint256 amount) public asCaller assumeHolder(to) {
        token.mint(to, amount);
    }

    function burn(address from, uint256 amount) public asCaller {
        token.burn(from, amount);
    }

    function approve(address spender, uint256 amount) public asCaller returns (bool) {
        return token.approve(spender, amount);
    }

    /*
     * helpers
     */

    modifier asCaller() {
        vm.startPrank(msg.sender);
        _;
        vm.stopPrank();
    }

    modifier assumeHolder(address account) {
        vm.assume(_contains(holders, account));
        _;
    }

    function _contains(address[] storage array, address value) internal view returns (bool) {
        for (uint256 i = 0; i < array.length; i++) {
            if (array[i] == value) {
                return true;
            }
        }
        return false;
    }

    // invariant: the sum of balances must equal the total supply
    function invariant_sumOfBalancesEqualsTotalSupply() public view {
        uint256 sumOfBalances = 0;
        for (uint256 i = 0; i < holders.length; i++) {
            sumOfBalances += token.balanceOf(holders[i]);
        }
        assertEq(sumOfBalances, token.totalSupply());
    }
}
