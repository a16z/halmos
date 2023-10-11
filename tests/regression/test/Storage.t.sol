// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import "../src/Storage.sol";

/// @custom:halmos --symbolic-storage
contract StorageTest is Storage {
    function check_setMap1(uint k, uint v) public {
        setMap1(k, v);
        assert(map1[k] == v);
    }

    function check_setMap2(uint k1, uint k2, uint v) public {
        setMap2(k1, k2, v);
        assert(map2[k1][k2] == v);
    }

    function check_setMap3(uint k1, uint k2, uint k3, uint v) public {
        setMap3(k1, k2, k3, v);
        assert(map3[k1][k2][k3] == v);
    }

    function check_addArr1(uint v) public {
        uint size = arr1.length;
        addArr1(v);
        assert(arr1.length == size + 1);
        assert(arr1[size] == v);
    }

    function check_addArr2(uint i, uint v) public {
        uint size = arr2[i].length;
        addArr2(i, v);
        assert(arr2[i].length == size + 1);
        assert(arr2[i][size] == v);
    }

    function check_addMap1Arr1(uint k, uint v) public {
        uint size = map1Arr1[k].length;
        addMap1Arr1(k, v);
        assert(map1Arr1[k].length == size + 1);
        assert(map1Arr1[k][size] == v);
    }
}
