// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract Storage {
    uint public num;

    mapping (uint => uint) public map1;
    mapping (uint => mapping (uint => uint)) public map2;
    mapping (uint => mapping (uint => mapping (uint => uint))) public map3;

    uint[] public arr1;
    uint[][] public arr2;

    mapping (uint => uint[]) public map1Arr1;

    constructor () { }

    function setMap1(uint k, uint v) public {
        map1[k] = v;
    }

    function setMap2(uint k1, uint k2, uint v) public {
        map2[k1][k2] = v;
    }

    function setMap3(uint k1, uint k2, uint k3, uint v) public {
        map3[k1][k2][k3] = v;
    }

    function addArr1(uint v) public {
        arr1.push(v);
    }

    function addArr2(uint i, uint v) public {
        arr2[i].push(v);
    }

    function addMap1Arr1(uint k, uint v) public {
        map1Arr1[k].push(v);
    }
}
