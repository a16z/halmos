# SPDX-License-Identifier: AGPL-3.0

"""
EVM version (hard fork) setting (a16z/halmos#128).

The version determines which opcodes are available: executing an opcode introduced
by a later fork halts the current frame with an invalid-opcode error, as on a node
running that fork. It also selects the semantics of SELFDESTRUCT (EIP-6780, Cancun).

When no version is given, the `evmVersion` the test contract was compiled for is
used (from the compiler metadata), falling back to the latest supported fork.
"""

from dolmos.contract import (
    OP_BASEFEE,
    OP_BLOBBASEFEE,
    OP_BLOBHASH,
    OP_CHAINID,
    OP_CLZ,
    OP_CREATE2,
    OP_DELEGATECALL,
    OP_EXTCODEHASH,
    OP_MCOPY,
    OP_PUSH0,
    OP_RETURNDATACOPY,
    OP_RETURNDATASIZE,
    OP_REVERT,
    OP_SAR,
    OP_SELFBALANCE,
    OP_SHL,
    OP_SHR,
    OP_STATICCALL,
    OP_TLOAD,
    OP_TSTORE,
)

# supported forks, in chronological order (solc/foundry names)
EVM_VERSIONS = (
    "homestead",
    "tangerineWhistle",
    "spuriousDragon",
    "byzantium",
    "constantinople",
    "petersburg",
    "istanbul",
    "berlin",
    "london",
    "paris",
    "shanghai",
    "cancun",
    "prague",
    "osaka",
)

LATEST_EVM_VERSION = EVM_VERSIONS[-1]

# alternative names accepted on input
EVM_VERSION_ALIASES = {
    "merge": "paris",
    "frontier": "homestead",  # frontier-only semantics are not modeled
}

# fork that introduced each opcode, for opcodes not available since homestead
OPCODE_INTRODUCED_IN = {
    OP_DELEGATECALL: "homestead",
    OP_REVERT: "byzantium",
    OP_RETURNDATASIZE: "byzantium",
    OP_RETURNDATACOPY: "byzantium",
    OP_STATICCALL: "byzantium",
    OP_SHL: "constantinople",
    OP_SHR: "constantinople",
    OP_SAR: "constantinople",
    OP_CREATE2: "constantinople",
    OP_EXTCODEHASH: "constantinople",
    OP_CHAINID: "istanbul",
    OP_SELFBALANCE: "istanbul",
    OP_BASEFEE: "london",
    OP_PUSH0: "shanghai",
    OP_TLOAD: "cancun",
    OP_TSTORE: "cancun",
    OP_MCOPY: "cancun",
    OP_BLOBHASH: "cancun",
    OP_BLOBBASEFEE: "cancun",
    OP_CLZ: "osaka",
}


def normalize_evm_version(name: str) -> str | None:
    """Returns the canonical fork name, or None if the name is not supported"""
    name = EVM_VERSION_ALIASES.get(name, name)
    for version in EVM_VERSIONS:
        if version.lower() == name.lower():
            return version
    return None


def fork_index(version: str) -> int:
    return EVM_VERSIONS.index(version)


def is_at_least(version: str, fork: str) -> bool:
    return fork_index(version) >= fork_index(fork)


def unavailable_opcodes(version: str) -> frozenset[int]:
    """Opcodes introduced after the given fork"""
    index = fork_index(version)
    return frozenset(
        opcode
        for opcode, fork in OPCODE_INTRODUCED_IN.items()
        if fork_index(fork) > index
    )


def evm_version_from_metadata(contract_json: dict) -> str | None:
    """Returns the evmVersion found in the compiler metadata of a build artifact"""
    metadata = contract_json.get("metadata")
    if not isinstance(metadata, dict):
        return None
    settings = metadata.get("settings")
    if not isinstance(settings, dict):
        return None
    version = settings.get("evmVersion")
    return version if isinstance(version, str) else None
