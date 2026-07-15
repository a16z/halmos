// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {Test} from "forge-std/Test.sol";

// resolves https://github.com/a16z/halmos/issues/178
//
// Demonstrates the payable-multicall pattern popularized by
// Uniswap/v3-periphery (see Uniswap/v3-periphery#52).
//
// The `payable` on `multicall` lets msg.value flow through delegatecall
// to every subcall unchanged, so a single msg.value can be counted more
// than once by any subcall that reads `msg.value` for accounting
// (deposit-shaped functions, in particular).
//
// The counterexample halmos finds: with any positive `amount`, batching
// two `deposit()` subcalls credits the caller `2 * amount` for a single
// `amount` payment.

abstract contract Multicall {
    function multicall(bytes[] calldata data) external payable returns (bytes[] memory results) {
        results = new bytes[](data.length);
        for (uint256 i = 0; i < data.length; i++) {
            (bool success, bytes memory result) = address(this).delegatecall(data[i]);
            require(success, "multicall subcall reverted");
            results[i] = result;
        }
    }
}

/// @notice WETH-shaped contract that credits msg.value on deposit.
///         Inheriting the payable Multicall makes deposit accountable for
///         the same msg.value more than once per batch.
contract VulnerableWETH is Multicall {
    mapping(address => uint256) public balanceOf;

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
    }
}

contract PayableMulticallTest is Test {
    VulnerableWETH weth;
    address alice = address(0xA11CE);

    function setUp() public {
        weth = new VulnerableWETH();
    }

    /// @notice counterexample: for any positive amount, batching two
    ///         deposit() subcalls credits alice 2 * amount while she only
    ///         paid amount. The `_fail` suffix follows the halmos
    ///         convention that the assertion is expected to be violated.
    function check_multicall_no_double_credit_fail(uint256 amount) external {
        vm.assume(amount > 0);
        vm.assume(amount < 2 ** 128);
        vm.deal(alice, amount);

        bytes[] memory data = new bytes[](2);
        data[0] = abi.encodeWithSelector(VulnerableWETH.deposit.selector);
        data[1] = abi.encodeWithSelector(VulnerableWETH.deposit.selector);

        vm.prank(alice);
        weth.multicall{value: amount}(data);

        // credit should never exceed what alice actually paid
        assertLe(weth.balanceOf(alice), amount);
    }

    /// @notice single-deposit control: without multicall, the invariant
    ///         holds. This anchors the counterexample above to the
    ///         payable-multicall pattern rather than to deposit() itself.
    function check_single_deposit_no_over_credit_pass(uint256 amount) external {
        vm.assume(amount > 0);
        vm.assume(amount < 2 ** 128);
        vm.deal(alice, amount);

        vm.prank(alice);
        weth.deposit{value: amount}();

        assertLe(weth.balanceOf(alice), amount);
    }
}
