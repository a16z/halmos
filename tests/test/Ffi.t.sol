// SPDX-License-Identifier: Unlicensed
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "forge-std/console2.sol";

/**
 * @dev The interface of this cheat code is called `_CheatCodes`,
 * so you can use the `CheatCodes` interface (see here:
 * https://book.getfoundry.sh/cheatcodes/?highlight=CheatCodes#cheatcode-types)
 * in other test files without errors.
 */
// solhint-disable-next-line contract-name-camelcase
interface _CheatCodes {
    function ffi(string[] calldata) external returns (bytes memory);
}



contract FfiTest is Test {
    // address private constant HEVM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));
    /**
     * @dev Initialises `cheatCodes` in order to use the foreign function interface (ffi)
     */
    //_CheatCodes private cheatCodes = _CheatCodes(HEVM_ADDRESS);
    _CheatCodes private cheatCodes = _CheatCodes(address(uint160(uint256(keccak256("hevm cheat code")))));

    /**
     * @dev ffi is a function that takes a list of strings and returns a bytes array.
     */
    function ffi(string[] memory _cmds) internal returns (bytes memory) {
        return cheatCodes.ffi(_cmds);
    }

    function testFFI_HexOutput() public {
        string[] memory inputs = new string[](3);
        inputs[0] = "echo";
        inputs[1] = "-n";
        inputs[2] = /* "arbitrary string" abi.encoded hex representation */"0x0000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001061726269747261727920737472696e6700000000000000000000000000000000";

        bytes memory res = ffi(inputs);

        bytes32 expected = keccak256(abi.encodePacked("arbitrary string"));
        bytes32 output = keccak256(abi.encodePacked(abi.decode(res, (string))));

        assert(expected == output);
    }

    function testFFI_StringOutput() public {
        string memory str = "arbitrary string";

        string[] memory inputs = new string[](3);
        inputs[0] = "echo";
        inputs[1] = "-n";
        inputs[2] = str;

        bytes32 expected = keccak256(abi.encodePacked(str));
        bytes32 output = keccak256(
            ffi(inputs) /* Perform ffi */
        );

        assert(expected == output);
    }

    function testFFI_Stderr() public {
        string[] memory inputs = new string[](3);
        inputs[0] = "logger";
        inputs[1] = "-s";
        inputs[2] = "Error!";

        bytes32 output = keccak256(
            vm.ffi(inputs) /* Perform ffi that generates non empty stderr */
        );

        /* TODO: fix bug in sha3 of empty bytes
        bytes32 expected = keccak256(abi.encodePacked(""));
        assert(expected == output);
        */
    }

    function testFFI_Failure() public {
        string[] memory inputs = new string[](1);
        inputs[0] = "must_fail";

        bytes32 output = keccak256(
            vm.ffi(inputs) /* Perform ffi that generates non empty stderr */
        );
    }
}
