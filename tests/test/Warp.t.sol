// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract C is Test {
    constructor(uint time) {
        vm.warp(time);
    }
}

contract Ext is Test {
    function warp(uint time) public {
        vm.warp(time);
    }
}

contract WarpTest is Test {
    Ext ext;
    C c;

    function setUp() public {
        ext = new Ext();
        vm.warp(1000);
    }

    function warp(uint time) public {
        vm.warp(time);
    }

    function check_warp(uint time) public {
        vm.warp(time);
        assert(block.timestamp == time);
    }

    function check_warp_Internal(uint time) public {
        warp(time);
        assert(block.timestamp == time);
    }

    function check_warp_External(uint time) public {
        ext.warp(time);
        assert(block.timestamp == time);
    }

    function check_warp_ExternalSelf(uint time) public {
        this.warp(time);
        assert(block.timestamp == time);
    }

    function check_warp_New(uint time) public {
        c = new C(time);
        assert(block.timestamp == time);
    }

    function check_warp_Reset(uint time1, uint time2) public {
        vm.warp(time1);
        assert(block.timestamp == time1);
        vm.warp(time2);
        assert(block.timestamp == time2);
    }

    function check_warp_SetUp() public view {
        assert(block.timestamp == 1000);
    }
}
