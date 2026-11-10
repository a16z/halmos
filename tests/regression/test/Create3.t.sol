// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

/// @notice minimal CREATE3 library, as found in 0xsequence/create3, solmate and solady
/// @dev see upstream halmos issue #217
library Create3 {
    bytes internal constant PROXY_CHILD_BYTECODE = hex"67363d3d37363d34f03d5260086018f3";

    bytes32 internal constant KECCAK256_PROXY_CHILD_BYTECODE =
        0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f;

    /// @dev keccak256(rlp([keccak256(0xff ++ address(this) ++ salt ++ keccak256(childBytecode))[12:], 0x01]))
    function addressOf(bytes32 salt) internal view returns (address) {
        address proxy = address(
            uint160(uint256(keccak256(abi.encodePacked(hex"ff", address(this), salt, KECCAK256_PROXY_CHILD_BYTECODE))))
        );

        return address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", proxy, hex"01")))));
    }

    function create3(bytes32 salt, bytes memory creationCode) internal returns (address addr) {
        bytes memory proxyCode = PROXY_CHILD_BYTECODE;

        addr = addressOf(salt);
        require(addr.code.length == 0, "TargetAlreadyExists");

        address proxy;
        assembly {
            proxy := create2(0, add(proxyCode, 32), mload(proxyCode), salt)
        }
        require(proxy != address(0), "ErrorCreatingProxy");

        (bool success,) = proxy.call(creationCode);
        require(success && addr.code.length != 0, "ErrorCreatingContract");
    }
}

contract Counter {
    uint256 public number;

    constructor(uint256 _number) {
        number = _number;
    }

    function increment() public {
        number++;
    }
}

contract Create3Test is Test {
    function check_create3(uint256 initial) public {
        vm.assume(initial < type(uint256).max);

        bytes32 salt = keccak256("counter");

        address predicted = Create3.addressOf(salt);
        address deployed = Create3.create3(salt, abi.encodePacked(type(Counter).creationCode, abi.encode(initial)));

        assertEq(deployed, predicted);
        assertEq(Counter(deployed).number(), initial);

        Counter(deployed).increment();
        assertEq(Counter(deployed).number(), initial + 1);
    }

    /// @notice a CREATE deployment must land on keccak256(rlp([sender, nonce]))
    function check_create_address_prediction() public {
        // the test contract has nonce 1 before its first deployment
        address predicted = address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", address(this), hex"01")))));

        Counter c = new Counter(0);

        assertEq(address(c), predicted);
    }

    function check_create_address_prediction_nonce2() public {
        new Counter(0);

        address predicted = address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", address(this), hex"02")))));

        Counter c = new Counter(0);

        assertEq(address(c), predicted);
    }
}

contract NonceTest is Test {
    function check_nonce_of_test_contract() public {
        assertEq(vm.getNonce(address(this)), 1);

        new Counter(0);
        assertEq(vm.getNonce(address(this)), 2);

        new Counter(0);
        assertEq(vm.getNonce(address(this)), 3);
    }

    function check_nonce_of_created_contract() public {
        Counter c = new Counter(0);

        // a newly created account starts at nonce 1 (EIP-161)
        assertEq(vm.getNonce(address(c)), 1);
    }

    function check_setNonce() public {
        address eoa = address(0x1234);
        assertEq(vm.getNonce(eoa), 0);

        vm.setNonce(eoa, 7);
        assertEq(vm.getNonce(eoa), 7);

        // setNonce() can only increase the nonce, setNonceUnsafe() can decrease it
        vm.setNonceUnsafe(eoa, 3);
        assertEq(vm.getNonce(eoa), 3);

        vm.resetNonce(eoa);
        assertEq(vm.getNonce(eoa), 0);
    }

    function check_resetNonce_of_contract() public {
        Counter c = new Counter(0);

        vm.setNonce(address(c), 9);
        assertEq(vm.getNonce(address(c)), 9);

        // resets to 1 for contract accounts
        vm.resetNonce(address(c));
        assertEq(vm.getNonce(address(c)), 1);
    }

    /// @notice setNonce() must change the address of the next deployment
    function check_setNonce_changes_create_address() public {
        vm.setNonce(address(this), 42);

        address predicted =
            address(uint160(uint256(keccak256(abi.encodePacked(hex"d694", address(this), bytes1(0x2a))))));

        Counter c = new Counter(0);

        assertEq(address(c), predicted);
    }
}
