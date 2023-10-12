// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

contract ByteTest {
    function byte1(uint i, uint x) public pure returns (uint r) {
        assembly { r := byte(i, x) }
    }

    function byte2(uint i, uint x) public pure returns (uint) {
        if (i >= 32) return 0;
        return (x >> (248-i*8)) & 0xff;
    }

    function byte3(uint i, uint x) public pure returns (uint) {
        if (i >= 32) return 0;
        bytes memory b = new bytes(32);
        assembly { mstore(add(b, 32), x) }
        return uint(uint8(bytes1(b[i]))); // TODO: Not supported: MLOAD symbolic memory offset: 160 + p_i_uint256
    }

    function check_byte(uint i, uint x) pure public {
        uint r1 = byte1(i, x);
        uint r2 = byte2(i, x);
    //  uint r3 = byte3(i, x); // not supported
        assert(r1 == r2);
    //  assert(r1 == r3);
    }
}

contract SymbolicByteTest {
    function check_SymbolicByteIndex(uint8 x, uint8 i) public pure returns (uint r) {
        if (x > 10) assert(false); // expected to fail
        assembly {
            r := byte(i, x)
        }
        assert(r == 0); // expected to fail with counterexample
    }
}
