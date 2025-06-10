# SPDX-License-Identifier: AGPL-3.0

from __future__ import annotations

import os

from dotenv import find_dotenv, load_dotenv

from halmos.logs import debug
from halmos.utils import Address, uint160


def init_env(path: str | None = None):
    if path is None:
        path = find_dotenv(usecwd=True)

    if not path:
        debug("no .env file found")
        return

    if not os.path.exists(path):
        debug(f"file {path} does not exist")
        return

    if os.path.isdir(path):
        path = os.path.join(path, ".env")

    if os.path.isfile(path):
        debug(f"loading .env from {path}")
        load_dotenv(path)

    debug(f"file {path} is not a file")


def exists(key: str) -> bool:
    return os.getenv(key) is not None


def parse_bytes32(value: str, expected_hexstr_len: int = 64) -> bytes:
    if not value.startswith("0x"):
        raise ValueError(f"Missing 0x prefix: {value}")

    value = value[2:]
    if len(value) != expected_hexstr_len:
        raise ValueError(
            f"Expected {expected_hexstr_len} characters, got {len(value)}: {value}"
        )
    return bytes.fromhex(value.rjust(64, "0"))


def get_string(key: str, default: str | None = None) -> str:
    value = os.getenv(key, default)
    if value is None:
        raise KeyError(key)
    return value


def get_int(key: str) -> int:
    """
    Returns the concrete integer value of the environment variable.

    Raises KeyError if the environment variable is not set.
    Raises ValueError if the environment variable is not a valid integer.
    """

    value = get_string(key)
    return int(value, 0)  # auto-detects base (0x or decimal), supports sign


def get_uint(key: str) -> int:
    """
    Returns the concrete unsigned integer value of the environment variable.

    Raises KeyError if the environment variable is not set.
    Raises ValueError if the environment variable is not a valid unsigned integer.
    """

    value = get_string(key)
    result = int(value, 0)  # auto-detects base (0x or decimal), supports sign
    if result < 0:
        raise ValueError("value must be non-negative")
    return result


def get_bool(key: str) -> bool:
    """
    Returns the concrete boolean value of the environment variable.

    Raises KeyError if the environment variable is not set.
    Raises ValueError if the environment variable is not a valid boolean.
    """

    value = get_string(key)

    match value.lower():
        case "true":
            return True
        case "false":
            return False
        case _:
            raise ValueError(value)


def get_address(key: str) -> Address:
    addr_str = get_string(key)
    addr_bytes = parse_bytes32(addr_str, expected_hexstr_len=40)
    return uint160(addr_bytes)


def get_bytes32(key: str) -> bytes:
    value = get_string(key)
    return parse_bytes32(value, expected_hexstr_len=64)


def get_bytes(key: str) -> bytes:
    value = get_string(key)
    # optional 0x prefix
    if value.startswith("0x"):
        value = value[2:]
    return bytes.fromhex(value)


def get_int_array(key: str, delimiter: str = ",") -> list[bytes]:
    value = get_string(key)
    parts = [x.strip() for x in value.split(delimiter)]

    # may raise ValueError if not a valid integer
    # may raise OverflowError if too large
    # base 0 supports hex/dec
    return [int(x, 0).to_bytes(32, "big", signed=True) for x in parts]


def get_uint_array(key: str, delimiter=",") -> list[int]:
    value = get_string(key)
    return [int(x.strip()).to_bytes(32, "big") for x in value.split(delimiter)]


def get_address_array(key: str, delimiter=",") -> list[Address]:
    value = get_string(key)
    addresses = [x.strip() for x in value.split(delimiter)]
    return [
        uint160(parse_bytes32(addr_str, expected_hexstr_len=40))
        for addr_str in addresses
    ]


def get_bool_array(key: str, delimiter=",") -> list[bool]:
    value = get_string(key)
    bool_array = [x.strip() for x in value.split(delimiter)]
    return [x.lower() in ["1", "true", "yes"] for x in bool_array]


def get_bytes32_array(key: str, delimiter=",") -> list[bytes]:
    value = get_string(key)
    parts = [x.strip() for x in value.split(delimiter)]
    return [parse_bytes32(part, expected_hexstr_len=64) for part in parts]


def get_string_array(key: str, delimiter=",") -> list[str]:
    value = get_string(key)
    return [x.strip() for x in value.split(delimiter)]


def get_bytes_array(key: str, delimiter=",") -> list[bytes]:
    value = get_string(key)
    return [bytes.fromhex(x.strip().replace("0x", "")) for x in value.split(delimiter)]
