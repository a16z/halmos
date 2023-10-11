// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract Storage {
    struct Tuple1 {
        uint x;
    }

    struct Tuple2 {
        uint y;
        uint z;
    }

    // m[k].f: #(k.m)+f                         km.f
    mapping (uint => uint) public map1_uint;
    mapping (uint => Tuple1) public map1_tuple1;
    mapping (uint => Tuple2) public map1_tuple2;

    // m[k][l].f: #(l.#(k.m))+f                 lkm.0.f
    mapping (uint => mapping (uint => uint)) public map2_uint;
    mapping (uint => mapping (uint => Tuple1)) public map2_tuple1;
    mapping (uint => mapping (uint => Tuple2)) public map2_tuple2;

    // a[i].f: #(a)+i*n+f                       a._
    uint[] public arr1_uint;
    Tuple1[] public arr1_tuple1;
    Tuple2[] public arr1_tuple2;

    // a[i][j].f: #(#(a)+i)+j*n+f               a.i._
    uint[][] public arr2_uint;
    Tuple1[][] public arr2_tuple1;
    Tuple2[][] public arr2_tuple2;

    // m[k][i].f: #(#(k.m))+i*n+f               km.0._
    mapping (uint => uint[]) public map1_arr1_uint;
    mapping (uint => Tuple1[]) public map1_arr1_tuple1;
    mapping (uint => Tuple2[]) public map1_arr1_tuple2;

    // a[i][k].f: #(k.(#(a)+i))+f               ka.i.f
    mapping (uint => uint)[] public arr1_map1_uint;
    mapping (uint => Tuple1)[] public arr1_map1_tuple1;
    mapping (uint => Tuple2)[] public arr1_map1_tuple2;

    // a[i][k][j].f: #(#(k.(#(a)+i)))+j*n+f     ka.i.0._
    mapping (uint => uint[])[] public arr1_map1_arr1_uint;
    mapping (uint => Tuple1[])[] public arr1_map1_arr1_tuple1;
    mapping (uint => Tuple2[])[] public arr1_map1_arr1_tuple2;

    constructor () { }

    function maxsize_arr1() public {
        assembly {
            sstore(arr1_uint.slot, not(0))
            sstore(arr1_tuple1.slot, not(0))
            sstore(arr1_tuple2.slot, not(0))
        }
    }

    function maxsize_arr2() public {
        assembly {
            sstore(arr2_uint.slot, not(0))
            sstore(arr2_tuple1.slot, not(0))
            sstore(arr2_tuple2.slot, not(0))
        }
    }

    function maxsize_arr2(uint i) public {
        uint[]   storage arr2_uint_i   = arr2_uint[i];
        Tuple1[] storage arr2_tuple1_i = arr2_tuple1[i];
        Tuple2[] storage arr2_tuple2_i = arr2_tuple2[i];
        assembly {
            sstore(arr2_uint_i.slot, not(0))
            sstore(arr2_tuple1_i.slot, not(0))
            sstore(arr2_tuple2_i.slot, not(0))
        }
    }

    function maxsize_map1_arr1(uint k) public {
        uint[]   storage map1_arr1_uint_k   = map1_arr1_uint[k];
        Tuple1[] storage map1_arr1_tuple1_k = map1_arr1_tuple1[k];
        Tuple2[] storage map1_arr1_tuple2_k = map1_arr1_tuple2[k];
        assembly {
            sstore(map1_arr1_uint_k.slot, not(0))
            sstore(map1_arr1_tuple1_k.slot, not(0))
            sstore(map1_arr1_tuple2_k.slot, not(0))
        }
    }

    function maxsize_arr1_map1() public {
        assembly {
            sstore(arr1_map1_uint.slot, not(0))
            sstore(arr1_map1_tuple1.slot, not(0))
            sstore(arr1_map1_tuple2.slot, not(0))
        }
    }

    function maxsize_arr1_map1_arr1() public {
        assembly {
            sstore(arr1_map1_arr1_uint.slot, not(0))
            sstore(arr1_map1_arr1_tuple1.slot, not(0))
            sstore(arr1_map1_arr1_tuple2.slot, not(0))
        }
    }

    function maxsize_arr1_map1_arr1(uint i, uint k) public {
        uint[]   storage arr1_map1_arr1_uint_i_k   = arr1_map1_arr1_uint[i][k];
        Tuple1[] storage arr1_map1_arr1_tuple1_i_k = arr1_map1_arr1_tuple1[i][k];
        Tuple2[] storage arr1_map1_arr1_tuple2_i_k = arr1_map1_arr1_tuple2[i][k];
        assembly {
            sstore(arr1_map1_arr1_uint_i_k.slot, not(0))
            sstore(arr1_map1_arr1_tuple1_i_k.slot, not(0))
            sstore(arr1_map1_arr1_tuple2_i_k.slot, not(0))
        }
    }
}

contract Storage2Test is Storage, Test {
    struct Param {
        uint k11; uint v11;
        uint k12; uint v12;
        uint k13; uint v13;
        uint k14; uint v14;

        uint k21; uint l21; uint v21;
        uint k22; uint l22; uint v22;
        uint k23; uint l23; uint v23;
        uint k24; uint l24; uint v24;

        uint32 i31; uint v31;
        uint32 i32; uint v32;
        uint32 i33; uint v33;
        uint32 i34; uint v34;

        uint32 i41; uint32 j41; uint v41;
        uint32 i42; uint32 j42; uint v42;
        uint32 i43; uint32 j43; uint v43;
        uint32 i44; uint32 j44; uint v44;

        uint k51; uint32 i51; uint v51;
        uint k52; uint32 i52; uint v52;
        uint k53; uint32 i53; uint v53;
        uint k54; uint32 i54; uint v54;

        uint32 i61; uint k61; uint v61;
        uint32 i62; uint k62; uint v62;
        uint32 i63; uint k63; uint v63;
        uint32 i64; uint k64; uint v64;

        uint32 i71; uint k71; uint32 j71; uint v71;
        uint32 i72; uint k72; uint32 j72; uint v72;
        uint32 i73; uint k73; uint32 j73; uint v73;
        uint32 i74; uint k74; uint32 j74; uint v74;
    }

    function check_set(Param memory p) public {
        map1_uint  [p.k11]   = p.v11;
        map1_tuple1[p.k12].x = p.v12;
        map1_tuple2[p.k13].y = p.v13;
        map1_tuple2[p.k14].z = p.v14;

        map2_uint  [p.k21][p.l21]   = p.v21;
        map2_tuple1[p.k22][p.l22].x = p.v22;
        map2_tuple2[p.k23][p.l23].y = p.v23;
        map2_tuple2[p.k24][p.l24].z = p.v24;

        maxsize_arr1();
        arr1_uint  [p.i31]   = p.v31;
        arr1_tuple1[p.i32].x = p.v32;
        arr1_tuple2[p.i33].y = p.v33;
        arr1_tuple2[p.i34].z = p.v34;

        maxsize_arr2();
        maxsize_arr2(p.i41);
        maxsize_arr2(p.i42);
        maxsize_arr2(p.i43);
        maxsize_arr2(p.i44);
        arr2_uint  [p.i41][p.j41]   = p.v41;
        arr2_tuple1[p.i42][p.j42].x = p.v42;
        arr2_tuple2[p.i43][p.j43].y = p.v43;
        arr2_tuple2[p.i44][p.j44].z = p.v44;

        maxsize_map1_arr1(p.k51);
        maxsize_map1_arr1(p.k52);
        maxsize_map1_arr1(p.k53);
        maxsize_map1_arr1(p.k54);
        map1_arr1_uint  [p.k51][p.i51]   = p.v51;
        map1_arr1_tuple1[p.k52][p.i52].x = p.v52;
        map1_arr1_tuple2[p.k53][p.i53].y = p.v53;
        map1_arr1_tuple2[p.k54][p.i54].z = p.v54;

        maxsize_arr1_map1();
        arr1_map1_uint  [p.i61][p.k61]   = p.v61;
        arr1_map1_tuple1[p.i62][p.k62].x = p.v62;
        arr1_map1_tuple2[p.i63][p.k63].y = p.v63;
        arr1_map1_tuple2[p.i64][p.k64].z = p.v64;

        maxsize_arr1_map1_arr1();
        maxsize_arr1_map1_arr1(p.i71, p.k71);
        maxsize_arr1_map1_arr1(p.i72, p.k72);
        maxsize_arr1_map1_arr1(p.i73, p.k73);
        maxsize_arr1_map1_arr1(p.i74, p.k74);
        arr1_map1_arr1_uint  [p.i71][p.k71][p.j71]   = p.v71;
        arr1_map1_arr1_tuple1[p.i72][p.k72][p.j72].x = p.v72;
        arr1_map1_arr1_tuple2[p.i73][p.k73][p.j73].y = p.v73;
        arr1_map1_arr1_tuple2[p.i74][p.k74][p.j74].z = p.v74;

        //

        assert(map1_uint  [p.k11]   == p.v11);
        assert(map1_tuple1[p.k12].x == p.v12);
        assert(map1_tuple2[p.k13].y == p.v13);
        assert(map1_tuple2[p.k14].z == p.v14);

        assert(map2_uint  [p.k21][p.l21]   == p.v21);
        assert(map2_tuple1[p.k22][p.l22].x == p.v22);
        assert(map2_tuple2[p.k23][p.l23].y == p.v23);
        assert(map2_tuple2[p.k24][p.l24].z == p.v24);

        assert(arr1_uint  [p.i31]   == p.v31);
        assert(arr1_tuple1[p.i32].x == p.v32);
        assert(arr1_tuple2[p.i33].y == p.v33);
        assert(arr1_tuple2[p.i34].z == p.v34);

        assert(arr2_uint  [p.i41][p.j41]   == p.v41);
        assert(arr2_tuple1[p.i42][p.j42].x == p.v42);
        assert(arr2_tuple2[p.i43][p.j43].y == p.v43);
        assert(arr2_tuple2[p.i44][p.j44].z == p.v44);

        assert(map1_arr1_uint  [p.k51][p.i51]   == p.v51);
        assert(map1_arr1_tuple1[p.k52][p.i52].x == p.v52);
        assert(map1_arr1_tuple2[p.k53][p.i53].y == p.v53);
        assert(map1_arr1_tuple2[p.k54][p.i54].z == p.v54);

        assert(arr1_map1_uint  [p.i61][p.k61]   == p.v61);
        assert(arr1_map1_tuple1[p.i62][p.k62].x == p.v62);
        assert(arr1_map1_tuple2[p.i63][p.k63].y == p.v63);
        assert(arr1_map1_tuple2[p.i64][p.k64].z == p.v64);

        assert(arr1_map1_arr1_uint  [p.i71][p.k71][p.j71]   == p.v71);
        assert(arr1_map1_arr1_tuple1[p.i72][p.k72][p.j72].x == p.v72);
        assert(arr1_map1_arr1_tuple2[p.i73][p.k73][p.j73].y == p.v73);
        assert(arr1_map1_arr1_tuple2[p.i74][p.k74][p.j74].z == p.v74);
    }
}
