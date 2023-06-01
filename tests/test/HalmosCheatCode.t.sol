// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

interface Halmos {
    // Create a new symbolic uint value ranging over [0, 2**bitSize - 1] (inclusive)
    function createSymbolicUint(uint256 bitSize) external returns (uint256 value);

    // Create a new symbolic byte array with the given byte size
    function createSymbolicBytes(uint256 byteSize) external returns (bytes memory value);

    // Create a new symbolic uint256 value
    function createSymbolicUint256() external returns (uint256 value);

    // Create a new symbolic bytes32 value
    function createSymbolicBytes32() external returns (bytes32 value);

    // Create a new symbolic address value
    function createSymbolicAddress() external returns (address value);

    // Create a new symbolic boolean value
    function createSymbolicBool() external returns (bool value);
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
        assert(0 <= x && x <= type(uint256).max);
        assert(0 <= y && y <= type(uint160).max);
        assert(0 <= z && z <= type(uint8).max);
    }

    function testCreateSymbolicBytes() public {
        bytes memory data = halmos.createSymbolicBytes(2);
        uint x = uint(uint8(data[0]));
        uint y = uint(uint8(data[1]));
        assert(0 <= x && x <= type(uint8).max);
        assert(0 <= y && y <= type(uint8).max);
    }

    function testCreateSymbolicUint256() public {
        uint x = halmos.createSymbolicUint256();
        assert(0 <= x && x <= type(uint256).max);
    }

    function testCreateSymbolicBytes32() public {
        bytes32 x = halmos.createSymbolicBytes32();
        assert(0 <= uint(x) && uint(x) <= type(uint256).max);
        uint y; assembly { y := x }
        assert(0 <= y && y <= type(uint256).max);
    }

    function testCreateSymbolicAddress() public {
        address x = halmos.createSymbolicAddress();
        uint y; assembly { y := x }
        assert(0 <= y && y <= type(uint160).max);
    }

    function testCreateSymbolicBool() public {
        bool x = halmos.createSymbolicBool();
        uint y; assembly { y := x }
        assert(y == 0 || y == 1);
    }
}
