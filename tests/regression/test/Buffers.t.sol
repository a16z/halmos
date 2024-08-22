// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;
import "forge-std/Test.sol";

contract BuffersTest is Test {
    function check_calldatacopy_large_offset() public {
        uint256 index = 1 ether;
        uint256 value;
        assembly {
            calldatacopy(0, index, 32)
            value := mload(0)
        }

        assertEq(value, 0);
    }

    function check_calldataload_large_offset() public {
        uint256 index = 1 ether;
        uint256 value;
        assembly {
            value := calldataload(index)
        }

        assertEq(value, 0);
    }

    function check_codecopy_large_offset() public {
        uint256 index = 1 ether;
        uint256 value;
        assembly {
            codecopy(0, index, 32)
            value := mload(0)
        }

        assertEq(value, 0);
    }

    function check_codecopy_offset_across_boundary() public {
        uint256 index = address(this).code.length - 16;
        uint256 value;
        assembly {
            codecopy(0, index, 32)
            value := mload(0)
        }

        assertNotEq(value, 0);
    }

    function check_extcodecopy_boundary() public {
        address target = address(this);
        uint256 index = target.code.length - 16;
        uint256 value;
        assembly {
            extcodecopy(target, 0, index, 32)
            value := mload(0)
        }

        assertNotEq(value, 0);
    }
}
