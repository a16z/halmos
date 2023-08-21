// SPDX-License-Identifier: Unlicensed
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

/// @custom:halmos --ffi
contract FfiTest is Test {
    function check_FfiHexOutput() public {
        string[] memory inputs = new string[](2);
        inputs[0] = "echo";
        inputs[1] = /* "arbitrary string" abi.encoded hex representation */"0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001061726269747261727920737472696e6700000000000000000000000000000000";

        bytes memory res = vm.ffi(inputs);

        bytes32 expected = keccak256(abi.encodePacked("arbitrary string"));
        bytes32 output = keccak256(abi.encodePacked(abi.decode(res, (string))));

        assert(expected == output);
    }

    function check_FfiStringOutput() public {
        string memory str = "arbitrary string";

        string[] memory inputs = new string[](2);
        inputs[0] = "echo";
        inputs[1] = str;

        bytes32 expected = keccak256(abi.encodePacked(str));
        bytes32 output = keccak256(
            vm.ffi(inputs) /* Perform ffi */
        );

        assert(expected == output);
    }
}
