// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

interface Halmos {
    // Create a new symbolic uint256 value ranging over [0, 2**bitSize - 1] (inclusive)
    function createSymbolicUint(uint256 bitSize) external returns (uint256 value);

    // Create a new symbolic byte array with the given byte size
    function createSymbolicBytes(uint256 byteSize) external returns (bytes memory value);
}

abstract contract HalmosTest {
    // Halmos cheat code address: 0x23059c36bb741986638baf337ff4d70fd1c4ef91
    address internal constant HALMOS_ADDRESS = address(uint160(uint256(keccak256("halmos cheat code"))));

    Halmos internal constant halmos = Halmos(HALMOS_ADDRESS);
}

contract HalmosCheatCodeTest is HalmosTest {
    function testCreateSymbolicUint() public {
        uint x = halmos.createSymbolicUint(256);
        uint y = halmos.createSymbolicUint(160);
        uint z = halmos.createSymbolicUint(8);
        assert(x <= type(uint256).max);
        assert(y <= type(uint160).max);
        assert(z <= type(uint8).max);
    }

    function testCreateSymbolicBytes() public {
        bytes memory data = halmos.createSymbolicBytes(2);
        uint x = uint(uint8(data[0]));
        uint y = uint(uint8(data[1]));
        assert(x <= type(uint8).max);
        assert(y <= type(uint8).max);
    }
}
