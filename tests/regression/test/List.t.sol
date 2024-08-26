// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/List.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract ListTest is SymTest, Test, List {
    function setUp() public {
        svm.enableSymbolicStorage(address(this));
    }

    function check_add(uint x) public {
        uint oldSize = arr.length;
        vm.assume(oldSize < type(uint).max);
        add(x);
        uint newSize = arr.length;
        assert(oldSize < newSize);
        assert(oldSize + 1 == newSize);
        assert(arr[newSize-1] == x);
    }

    function check_remove() public {
        uint oldSize = arr.length;
        vm.assume(oldSize > 0);
        remove();
        uint newSize = arr.length;
        assert(oldSize > newSize);
        assert(oldSize == newSize + 1);
    }

    function check_set(uint i, uint x) public {
        vm.assume(i < arr.length);
        set(i, x);
        assert(arr[i] == x);
    }
}

contract ListTestTest is SymTest, Test {
    List list;

    function setUp() public {
        list = new List();
        list.add(1);
        svm.enableSymbolicStorage(address(list));
    }

    function check_add(uint x) public {
        uint oldSize = list.size();
        vm.assume(oldSize < type(uint).max);
        list.add(x);
        uint newSize = list.size();
        assert(oldSize < newSize);
        assert(oldSize + 1 == newSize);
        assert(list.arr(newSize-1) == x);
    }

    function check_remove() public {
        uint oldSize = list.size();
        vm.assume(oldSize > 0);
        list.remove();
        uint newSize = list.size();
        assert(oldSize > newSize);
        assert(oldSize == newSize + 1);
    }

    function check_set(uint i, uint x) public {
        vm.assume(i < list.size());
        list.set(i, x);
        assert(list.arr(i) == x);
    }
}
