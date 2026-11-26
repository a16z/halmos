// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract CalldataCexToken {
    mapping(address => uint256) public balanceOf;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function burn(uint256 amount) external {
        balanceOf[msg.sender] -= amount;
    }

    function burnAll() external {
        balanceOf[msg.sender] = 0;
    }
}

/// @notice the counterexamples tell which function the calldata of svm.createCalldata calls
/// @dev see upstream halmos issue #374
contract CreateCalldataCexTest is Test, SymTest {
    CalldataCexToken token;

    function setUp() public {
        token = new CalldataCexToken();
        token.mint(address(this), 100);
    }

    // counterexamples: burn(amount) with a positive amount, and burnAll() that has no argument
    function check_calldata_cex() public {
        bytes memory data = svm.createCalldata("CalldataCexToken");
        (bool success,) = address(token).call(data);
        vm.assume(success);
        assert(token.balanceOf(address(this)) >= 100);
    }
}
