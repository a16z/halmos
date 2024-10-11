// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";
import {SymTest} from "halmos-cheatcodes/SymTest.sol";

contract C1 {
    function foo(bytes calldata data) external {
        uint offset;
        uint size;
        // This simulates custom calldata decoding:
        // 1. Copy static portion of calldata into memory
        // 2. Read offset and size from the copied memory
        // 3. Copy the actual data using calldatacopy
        assembly {
            // Copy the first 68 bytes of calldata into memory
            // This includes:
            // - 4 bytes for function selector
            // - 32 bytes for offset
            // - 32 bytes for size
            calldatacopy(0, 0, 68)

            // Read offset and size from copied memory
            // Note: Proper concretization is crucial here.
            // Without it, reading the size would fail due to a symbolic memory offset.
            offset := mload(4)
            size := mload(add(4, offset))

            // Copy the actual data portion
            calldatacopy(68, 68, size)

            // Return the decoded data
            return(4, add(size, 64))
        }
    }
}

contract C2 {
    function foo(bytes calldata data) external returns (bytes memory) {
        uint offset;
        uint size;
        // This simulates standard calldata decoding:
        // 1. Read offset and size directly from calldata using calldataload
        // 2. Copy the entire calldata into memory
        // 3. Copy the actual data portion
        assembly {
            // Read offset and size directly from calldata
            offset := calldataload(4)
            size := calldataload(add(4, offset))

            // Copy the first 68 bytes of calldata into memory
            calldatacopy(0, 0, 68)

            // Copy the actual data portion
            calldatacopy(68, 68, size)

            // Return the decoded data
            return(4, add(size, 64))
        }
    }
}

contract ConcretizationTest is SymTest, Test {
    address c1;
    address c2;

    function setUp() public {
        c1 = address(new C1());
        c2 = address(new C2());
    }

    function check_custom_calldata_decoding() public {
        bytes memory data = svm.createCalldata("Concretization.t.sol", "C1");
        (bool success1, bytes memory retdata1) = c1.call(data);
        (bool success2, bytes memory retdata2) = c2.call(data);
        assertEq(success1, success2);
        assertEq(retdata1, retdata2);
    }

    function check_memory_index(uint idx) public {
        uint[3] memory arr = [uint(0), 1, 2];

        vm.assume(idx == 0 || idx == 1 || idx == 2);

        // there are three paths at this point
        assertEq(arr[idx], idx);
    }

    uint[3] arr = [0, 1, 2];
    function check_storage_slot(uint idx) public {
        vm.assume(idx == 0 || idx == 1 || idx == 2);
        assertEq(arr[idx], idx);
    }

    function check_calldata_index(bytes calldata data, uint idx) external {
        vm.assume(idx == 0 || idx == 1 || idx == 2);

        vm.assume(data.length > 2);

        vm.assume(data[0] == bytes1(uint8(0)));
        vm.assume(data[1] == bytes1(uint8(1)));
        vm.assume(data[2] == bytes1(uint8(2)));

        assertEq(data[idx], bytes1(uint8(idx)));
    }

    function check_memory_size(uint idx) public {
        uint[] memory arr;

        vm.assume(idx == 0 || idx == 1 || idx == 2 || idx == 3);

        arr = new uint[](idx);
        for (uint i = 0; i < idx; i++) {
            arr[i] = i;
        }

        assertEq(arr.length, idx);
        if (idx > 0) assertEq(arr[0], 0);
        if (idx > 1) assertEq(arr[1], 1);
        if (idx > 2) assertEq(arr[2], 2);
    }
}
