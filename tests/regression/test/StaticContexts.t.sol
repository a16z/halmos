// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract Dummy {}

contract StaticContextsTest is Test {
    event Log(uint256 x);

    uint256 x;

    function do_sstore() public {
        unchecked {
            x += 1;
        }
    }

    function do_log() public {
        emit Log(x);
    }

    function do_create() public {
        new Dummy();
    }

    function do_create2() public {
        new Dummy{salt: 0}();
    }

    function do_call_with_value() public {
        vm.deal(address(this), 1 ether);
        (bool success, ) = payable(address(this)).call{value: 1 ether}("");
        success; // silence warnings
    }

    function do_selfdestruct() public {
        selfdestruct(payable(address(0)));
    }

    function check_sstore_fails() public {
        (bool success, ) = address(this).staticcall(abi.encodeWithSignature("do_sstore()"));
        assertFalse(success);
    }

    function check_log_fails() public {
        (bool success, ) = address(this).staticcall(abi.encodeWithSignature("do_log()"));
        assertFalse(success);
    }

    function check_create_fails() public {
        (bool success, ) = address(this).staticcall(abi.encodeWithSignature("do_create()"));
        assertFalse(success);
    }

    function check_create2_fails() public {
        (bool success, ) = address(this).staticcall(abi.encodeWithSignature("do_create2()"));
        assertFalse(success);
    }

    // TODO: value check not implemented yet
    // function check_call_with_value_fails() public {
    //     (bool success, ) = address(this).staticcall(abi.encodeWithSignature("do_call_with_value()"));
    //     assertFalse(success);
    // }

    // TODO: selfdestruct not implemented yet
    // function check_selfdestruct_fails() public {
    //     (bool success, ) = address(this).staticcall(abi.encodeWithSignature("do_selfdestruct()"));
    //     assertFalse(success);
    // }
}
