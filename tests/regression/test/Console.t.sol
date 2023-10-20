// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {console2} from "forge-std/console2.sol";

contract ConsoleTest is Test {
    function check_log_uint() public view {
        console2.log("this is 0:", uint256(0));
        console2.log("this is 1:", uint256(1));

        console2.log(uint256(0));
        console2.log(uint256(1));

        console2.logUint(0);
        console2.logUint(1);
    }

    function check_log_int() public view {
        console2.log("this is -1:", -1);
        console2.log("this is 1:", int256(1));

        console2.log(-1);
        console2.log(int256(1));

        console2.logInt(-1);
        console2.logInt(int256(1));
    }

    function check_log_bytes() public view {
        bytes memory hello = "hello";
        bytes memory empty = "";
        console2.log("this is hello (bytes):");
        console2.logBytes(hello);
        console2.log("this is empty bytes:");
        console2.logBytes(empty);
    }

    function check_log_bytes32() public view {
        console2.log("this is keccak256(hello):");
        console2.logBytes32(keccak256("hello"));

        console2.log("this is keccak256():");
        console2.logBytes32(keccak256(""));
    }

    function check_log_address() public view {
        console2.log("this is address(0):", address(0));
        console2.log("this is address(this):", address(this));

        console2.log(address(0));
        console2.log(address(this));
    }

    function check_log_bool() public view {
        console2.log("this is true:", true);
        console2.log("this is false:", false);

        console2.log(true);
        console2.log(false);
    }

    function check_log_string() public view {
        string memory hello = "hello";
        string memory empty = "";
        console2.log("this is hello (string):", hello);
        console2.log("this is empty string:", empty);

        console2.log(hello);
        console2.log(empty);
    }

    function check_log_undecodable_string() public view {
        bytes memory badBytes = hex"ff";
        string memory bad = string(badBytes);
        console2.log("this is a string that won't decode to utf-8:", bad);
    }

    function check_log_unsupported() public {
        console2._sendLogPayload(abi.encodeWithSignature("doesNotExist()"));
    }
}
