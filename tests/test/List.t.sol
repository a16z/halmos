// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/List.sol";

/// @custom:halmos --symbolic-storage
contract ListTest is Test, List {
    function checkAdd(uint x) public {
        uint oldSize = arr.length;
        vm.assume(oldSize < type(uint).max);
        add(x);
        uint newSize = arr.length;
        assert(oldSize < newSize);
        assert(oldSize + 1 == newSize);
        assert(arr[newSize-1] == x);
    }

    function checkRemove() public {
        uint oldSize = arr.length;
        vm.assume(oldSize > 0);
        remove();
        uint newSize = arr.length;
        assert(oldSize > newSize);
        assert(oldSize == newSize + 1);
    }

    function checkSet(uint i, uint x) public {
        vm.assume(i < arr.length);
        set(i, x);
        assert(arr[i] == x);
    }
}

/// @custom:halmos --symbolic-storage
contract ListTestTest is Test {
    List list;

    function setUp() public {
        list = new List();
        list.add(1);
    }

    function checkAdd(uint x) public {
        uint oldSize = list.size();
        vm.assume(oldSize < type(uint).max);
        list.add(x);
        uint newSize = list.size();
        assert(oldSize < newSize);
        assert(oldSize + 1 == newSize);
        assert(list.arr(newSize-1) == x);
    }

    function checkRemove() public {
        uint oldSize = list.size();
        vm.assume(oldSize > 0);
        list.remove();
        uint newSize = list.size();
        assert(oldSize > newSize);
        assert(oldSize == newSize + 1);
    }

    function checkSet(uint i, uint x) public {
        vm.assume(i < list.size());
        list.set(i, x);
        assert(list.arr(i) == x);
    }
}
