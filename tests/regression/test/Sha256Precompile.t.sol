// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract Sha256Target {
    uint256 public marker;

    function hashOneByte() external {
        marker = 1;
        (bool success, bytes memory output) = address(2).staticcall(hex"01");
        require(success && output.length == 32);
    }

    function hashEmpty() external view {
        (bool success, bytes memory output) = address(2).staticcall("");
        require(success && output.length == 32);
    }
}

contract Sha256PrecompileTest is Test {
    Sha256Target target;

    function setUp() public {
        target = new Sha256Target();
        targetContract(address(target));
    }

    function check_sha256_inputs() public {
        target.hashEmpty();
        target.hashOneByte();
        assertEq(target.marker(), 1);
    }

    function check_sha256_symbolic_byte(bytes1 input) public view {
        bytes memory data = abi.encodePacked(input);
        (bool successFirst, bytes memory first) = address(2).staticcall(data);
        (bool successSecond, bytes memory second) = address(2).staticcall(data);

        assertTrue(successFirst && successSecond);
        assertEq(first.length, 32);
        assertEq(second.length, 32);
        assertEq(first, second);
    }

    /// @custom:halmos --invariant-depth 1
    function invariant_marker_zero() public view {
        // Expected counterexample: hashOneByte() reaches this state.
        assertEq(target.marker(), 0);
    }
}
