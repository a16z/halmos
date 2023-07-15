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

    function checkWarp(uint time) public {
        vm.warp(time);
        assert(block.timestamp == time);
    }

    function checkWarpInternal(uint time) public {
        warp(time);
        assert(block.timestamp == time);
    }

    function checkWarpExternal(uint time) public {
        ext.warp(time);
        assert(block.timestamp == time);
    }

    function checkWarpExternalSelf(uint time) public {
        this.warp(time);
        assert(block.timestamp == time);
    }

    function checkWarpNew(uint time) public {
        c = new C(time);
        assert(block.timestamp == time);
    }

    function checkWarpReset(uint time1, uint time2) public {
        vm.warp(time1);
        assert(block.timestamp == time1);
        vm.warp(time2);
        assert(block.timestamp == time2);
    }

    function checkWarpSetUp() public view {
        assert(block.timestamp == 1000);
    }
}
