// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

//
// Example from ItyFuzz paper (Figure 2): https://arxiv.org/pdf/2306.17135
//

contract SimpleState {
    uint counter = 0;

    function incr(uint x) public {
        require(x <= counter);
        counter += 1;
    }

    function decr(uint x) public {
        require(x >= counter);
        counter -= 1;
    }
}

contract SimpleStateTest is SymTest, Test {
    address target;

    function setUp() public {
        target = address(new SimpleState());
    }

    function buggy() public returns (bool) {
        uint counter = uint(vm.load(target, bytes32(0)));
        return counter == 10;
    }

    function check_buggy() public {
        bool success;

        (success,) = target.call(CreateCalldata(address(svm)).createCalldata("SimpleState"));
        vm.assume(success);
        (success,) = target.call(CreateCalldata(address(svm)).createCalldata("SimpleState"));
        vm.assume(success);
        (success,) = target.call(CreateCalldata(address(svm)).createCalldata("SimpleState"));
        vm.assume(success);
        (success,) = target.call(CreateCalldata(address(svm)).createCalldata("SimpleState"));
        vm.assume(success);
        (success,) = target.call(CreateCalldata(address(svm)).createCalldata("SimpleState"));
        vm.assume(success);
        (success,) = target.call(CreateCalldata(address(svm)).createCalldata("SimpleState"));
        vm.assume(success);
        (success,) = target.call(CreateCalldata(address(svm)).createCalldata("SimpleState"));
        vm.assume(success);
        (success,) = target.call(CreateCalldata(address(svm)).createCalldata("SimpleState"));
        vm.assume(success);
        (success,) = target.call(CreateCalldata(address(svm)).createCalldata("SimpleState"));
        vm.assume(success);
        (success,) = target.call(CreateCalldata(address(svm)).createCalldata("SimpleState"));
        vm.assume(success);

        assertFalse(buggy());
    }
}

// TODO: remove this after updating halmos-cheatcode submodule
interface CreateCalldata {
    function createCalldata(string memory contractName) external pure returns (bytes memory data);
}
