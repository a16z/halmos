// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract Storage5Test {
    uint[] arr0; // slot 0: keccak(0) = 0x290DECD9548B62A8D60345A988386FC84BA6BC95484008F6362F93160EF3E563 (ends with 1)
    uint[] arr1; // slot 1: keccak(1) = 0xB10E2D527612073B26EECDFD717E6A320CF44B4AFAC2B0732D9FCBE2B7FA0CF6 (ends with 0)
    uint dummy2; // slot 2
    uint dummy3; // slot 3
    uint dummy4; // slot 4
    uint[] arr5; // slot 5: keccak(5) = 0x036B6384B5ECA791C62761152D0C79BB0604C104A5FB6F4EB0703F3154BB3DB0 (ends with 00)

    function setUp() public {
        arr0.push(0);
        arr0.push(0);
        arr0.push(0);
        arr0.push(0);
        arr0.push(0);
        arr0.push(0);
        arr0.push(0);
        arr0.push(0);

        arr1.push(1);
        arr1.push(1);
        arr1.push(1);
        arr1.push(1);
        arr1.push(1);
        arr1.push(1);
        arr1.push(1);
        arr1.push(1);

        arr5.push(5);
        arr5.push(5);
        arr5.push(5);
        arr5.push(5);
        arr5.push(5);
        arr5.push(5);
        arr5.push(5);
        arr5.push(5);
    }

    function check_array_access(uint index) public {
        // The commented ones generate errors due to a failure in decoding
        // storage slots. This happens because the storage slot expression in
        // the form of an addition, `keccak(x) + (index % y)`, is automatically
        // simplified to a concatenation form when the keccak value ends with
        // zero bits and y is a power of two. This simplified form is not
        // currently supported by the decoding logic of halmos.

        assert(arr0[index % 1] == 0); // sload(keccak(0) + (index % 1))
        assert(arr0[index % 2] == 0); // sload(keccak(0) + (index % 2))
        assert(arr0[index % 3] == 0); // sload(keccak(0) + (index % 3))
        assert(arr0[index % 4] == 0); // sload(keccak(0) + (index % 4))
        assert(arr0[index % 5] == 0); // sload(keccak(0) + (index % 5))
        assert(arr0[index % 6] == 0); // sload(keccak(0) + (index % 6))
        assert(arr0[index % 7] == 0); // sload(keccak(0) + (index % 7))
        assert(arr0[index % 8] == 0); // sload(keccak(0) + (index % 8))

        assert(arr1[index % 1] == 1); // sload(keccak(1) + (index % 1))
//      assert(arr1[index % 2] == 1); // sload(keccak(1) + (index % 2)) => sload( keccak(1)[:31] ++ index[31:] )
        assert(arr1[index % 3] == 1); // sload(keccak(1) + (index % 3))
//      assert(arr1[index % 4] == 1); // sload(keccak(1) + (index % 4)) => sload( keccak(1)[:30] ++ index[30:] )
        assert(arr1[index % 5] == 1); // sload(keccak(1) + (index % 5))
        assert(arr1[index % 6] == 1); // sload(keccak(1) + (index % 6))
        assert(arr1[index % 7] == 1); // sload(keccak(1) + (index % 7))
        assert(arr1[index % 8] == 1); // sload(keccak(1) + (index % 8))

        assert(arr5[index % 1] == 5); // sload(keccak(5) + (index % 1))
//      assert(arr5[index % 2] == 5); // sload(keccak(5) + (index % 2)) => sload( keccak(5)[:31] ++ index[31:] )
        assert(arr5[index % 3] == 5); // sload(keccak(5) + (index % 3))
//      assert(arr5[index % 4] == 5); // sload(keccak(5) + (index % 4)) => sload( keccak(5)[:30] ++ index[30:] )
        assert(arr5[index % 5] == 5); // sload(keccak(5) + (index % 5))
        assert(arr5[index % 6] == 5); // sload(keccak(5) + (index % 6))
        assert(arr5[index % 7] == 5); // sload(keccak(5) + (index % 7))
//      assert(arr5[index % 8] == 5); // sload(keccak(5) + (index % 8)) => sload( keccak(5)[:29] ++ index[29:] )
    }
}
