// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

import "forge-std/Test.sol";

contract ProxyVault {
    bool public broken;
    uint256 public total;

    function deposit(uint256 x) external {
        total += x;
    }

    function breakIt() external {
        broken = true;
    }
}

/// minimal ERC-1967 proxy: the implementation is in the standard slot
contract ERC1967MiniProxy {
    bytes32 constant IMPLEMENTATION_SLOT =
        0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    constructor(address impl) {
        assembly {
            sstore(IMPLEMENTATION_SLOT, impl)
        }
    }

    fallback() external payable {
        assembly {
            let impl := sload(IMPLEMENTATION_SLOT)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), impl, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }
}

/// a proxy that keeps its implementation in a non-standard slot
contract CustomMiniProxy {
    bytes32 constant CUSTOM_SLOT = keccak256("custom.proxy.implementation");

    constructor(address impl) {
        bytes32 slot = CUSTOM_SLOT;
        assembly {
            sstore(slot, impl)
        }
    }

    fallback() external payable {
        bytes32 slot = CUSTOM_SLOT;
        assembly {
            let target := sload(slot)
            calldatacopy(0, 0, calldatasize())
            let ok := delegatecall(gas(), target, 0, calldatasize(), 0, 0)
            returndatacopy(0, 0, returndatasize())
            if iszero(ok) { revert(0, returndatasize()) }
            return(0, returndatasize())
        }
    }
}

/// invariant testing through an ERC-1967 proxy: the implementation's ABI is used
/// (halmos#553)
/// depth 1: deeper sequences repeat the idempotent breakIt(), and whether the repeated
/// state is deduplicated depends on the storage layout, which changes the number of
/// counterexamples
/// @custom:dolmos --invariant-depth 1
contract ProxyInvariantTest is Test {
    ProxyVault vault;

    function setUp() public {
        ProxyVault impl = new ProxyVault();
        vault = ProxyVault(address(new ERC1967MiniProxy(address(impl))));
        targetContract(address(vault));
    }

    function invariant_not_broken() public view {
        assert(!vault.broken());
    }
}

/// targetInterfaces() gives the ABI of a proxy that is not detected (halmos#553)
/// @custom:dolmos --invariant-depth 1
contract ProxyInterfaceInvariantTest is Test {
    ProxyVault vault;

    function setUp() public {
        ProxyVault impl = new ProxyVault();
        vault = ProxyVault(address(new CustomMiniProxy(address(impl))));
        string[] memory artifacts = new string[](1);
        artifacts[0] = "ProxyVault";
        targetInterface(FuzzInterface(address(vault), artifacts));
    }

    function invariant_not_broken() public view {
        assert(!vault.broken());
    }
}
