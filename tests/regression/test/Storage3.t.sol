// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import {SymTest} from "halmos-cheatcodes/SymTest.sol";
import {Test} from "forge-std/Test.sol";

contract Storage3 {
    mapping(bytes1 => uint) map_bytes1;

    mapping(bytes => uint) map_bytes;

    mapping(uint => mapping(bytes => uint)) map_uint_bytes;
    mapping(bytes => mapping(uint => uint)) map_bytes_uint;

    constructor () { }
}

contract Storage3Test is Storage3, SymTest, Test {
    struct Param {
        bytes1 x0;           uint v0;

                             uint v11;
                             uint v12;
                             uint v13;
                             uint v14;
                             uint v15;
                             uint v16;

                   uint y21; uint v21;
                   uint y22; uint v22;
                   uint y23; uint v23;
                   uint y24; uint v24;
                   uint y25; uint v25;
                   uint y26; uint v26;

                   uint y31; uint v31;
                   uint y32; uint v32;
                   uint y33; uint v33;
                   uint y34; uint v34;
                   uint y35; uint v35;
                   uint y36; uint v36;
    }

    function check_set(Param memory p) public {
        bytes[] memory x = new bytes[](40);

        x[11] = svm.createBytes( 1, "x11");
        x[12] = svm.createBytes(31, "x12");
        x[13] = svm.createBytes(32, "x13");
        x[14] = svm.createBytes(33, "x14");
        x[15] = svm.createBytes(64, "x15");
        x[16] = svm.createBytes(65, "x16");

        x[21] = svm.createBytes( 1, "x21");
        x[22] = svm.createBytes(31, "x22");
        x[23] = svm.createBytes(32, "x23");
        x[24] = svm.createBytes(33, "x24");
        x[25] = svm.createBytes(64, "x25");
        x[26] = svm.createBytes(65, "x26");

        x[31] = svm.createBytes( 1, "x31");
        x[32] = svm.createBytes(31, "x32");
        x[33] = svm.createBytes(32, "x33");
        x[34] = svm.createBytes(33, "x34");
        x[35] = svm.createBytes(64, "x35");
        x[36] = svm.createBytes(65, "x36");

        //

        map_bytes1[p.x0] = p.v0;

        map_bytes[x[11]] = p.v11;
        map_bytes[x[12]] = p.v12;
        map_bytes[x[13]] = p.v13;
        map_bytes[x[14]] = p.v14;
        map_bytes[x[15]] = p.v15;
        map_bytes[x[16]] = p.v16;

        map_uint_bytes[p.y21][x[21]] = p.v21;
        map_uint_bytes[p.y22][x[22]] = p.v22;
        map_uint_bytes[p.y23][x[23]] = p.v23;
        map_uint_bytes[p.y24][x[24]] = p.v24;
        map_uint_bytes[p.y25][x[25]] = p.v25;
        map_uint_bytes[p.y26][x[26]] = p.v26;

        map_bytes_uint[x[31]][p.y31] = p.v31;
        map_bytes_uint[x[32]][p.y32] = p.v32;
        map_bytes_uint[x[33]][p.y33] = p.v33;
        map_bytes_uint[x[34]][p.y34] = p.v34;
        map_bytes_uint[x[35]][p.y35] = p.v35;
        map_bytes_uint[x[36]][p.y36] = p.v36;

        //

        assert(map_bytes1[p.x0] == p.v0);

        assert(map_bytes[x[11]] == p.v11);
        assert(map_bytes[x[12]] == p.v12);
        assert(map_bytes[x[13]] == p.v13);
        assert(map_bytes[x[14]] == p.v14);
        assert(map_bytes[x[15]] == p.v15);
        assert(map_bytes[x[16]] == p.v16);

        assert(map_uint_bytes[p.y21][x[21]] == p.v21);
        assert(map_uint_bytes[p.y22][x[22]] == p.v22);
        assert(map_uint_bytes[p.y23][x[23]] == p.v23);
        assert(map_uint_bytes[p.y24][x[24]] == p.v24);
        assert(map_uint_bytes[p.y25][x[25]] == p.v25);
        assert(map_uint_bytes[p.y26][x[26]] == p.v26);

        assert(map_bytes_uint[x[31]][p.y31] == p.v31);
        assert(map_bytes_uint[x[32]][p.y32] == p.v32);
        assert(map_bytes_uint[x[33]][p.y33] == p.v33);
        assert(map_bytes_uint[x[34]][p.y34] == p.v34);
        assert(map_bytes_uint[x[35]][p.y35] == p.v35);
        assert(map_bytes_uint[x[36]][p.y36] == p.v36);
    }
}
