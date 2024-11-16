// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract SolverTest is SymTest, Test {
    uint[] numbers;

    function check_dynamic_array_overflow() public {
        numbers = new uint[](5); // shouldn't generate loop bounds warning
    }

    mapping(address => uint) balances;

    /// @custom:halmos --solver-timeout-exception 0
    function check_infeasible_halmos_exception(address sender, address receiver, uint value) public {
        svm.enableSymbolicStorage(address(this));

        uint oldSender = balances[sender];
        uint oldReceiver = balances[receiver];

        balances[sender] -= value;
        balances[receiver] += value;

        // solving this condition takes longer than the default branching condition timeout (1ms)
        if (balances[sender] + balances[receiver] != oldSender + oldReceiver) {
            // shouldn't reach here, because the condition is not satisfiable
            vm.prank(address(0));
            vm.prank(address(0)); // HalmosException will be triggered if reached
        }
    }
}
