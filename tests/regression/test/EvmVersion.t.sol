// SPDX-License-Identifier: AGPL-3.0
pragma solidity >=0.8.0 <0.9.0;

// EVM version setting (a16z/halmos#128): opcodes introduced after the selected fork are
// invalid. The probed opcodes run in contracts deployed from raw bytecode, so that the
// test contracts themselves (compiled for the default evm_version) are not affected.
abstract contract EvmVersionBase {
    function run(uint256 initcode, uint256 size) internal returns (bool success) {
        assembly {
            mstore(0, initcode)
            let target := create(0, 0, size)
            success := call(gas(), target, 0, 0, 0, 0, 0)
        }
    }

    // runtime: PUSH0 PUSH0 SSTORE STOP
    function push0() internal returns (bool) {
        return run(0x6004600a5f3960045ff35f5f5500000000000000000000000000000000000000, 14);
    }

    // runtime: PUSH1 1 PUSH0 TSTORE STOP
    function tstore() internal returns (bool) {
        return run(0x6005600a5f3960055ff360015f5d000000000000000000000000000000000000, 15);
    }

    // runtime: PUSH1 1 CLZ STOP
    function clz() internal returns (bool) {
        return run(0x6004600a5f3960045ff360011e00000000000000000000000000000000000000, 14);
    }
}

// default: the evm_version of the build (osaka)
contract EvmVersionDefaultTest is EvmVersionBase {
    function check_all_available() public {
        assert(push0());
        assert(tstore());
        assert(clz());
    }
}

/// @custom:dolmos --evm-version prague
contract EvmVersionPragueTest is EvmVersionBase {
    function check_clz_invalid() public {
        assert(push0());
        assert(tstore());
        assert(!clz());
    }
}

/// @custom:dolmos --evm-version shanghai
contract EvmVersionShanghaiTest is EvmVersionBase {
    function check_tstore_invalid() public {
        assert(push0());
        assert(!tstore());
        assert(!clz());
    }

    // expected failure: TSTORE is not available in shanghai
    function check_tstore_available_fail() public {
        assert(tstore());
    }
}
