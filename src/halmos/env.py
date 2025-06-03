# halmos/cheatcodes/env.py

import os

from dotenv import find_dotenv, load_dotenv

from halmos.logs import debug


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


def check_env_exists(key: str) -> bool:
    return os.getenv(key) is not None


def env_string(key: str, default: str | None = None) -> str:
    value = os.getenv(key, default)
    if value is None:
        raise ValueError(
            f"Environment variable '{key}' is not set and no default provided."
        )
    return value


def env_int(key: str, default: str | None = None) -> int:
    value = env_string(key, default=default)
    try:
        return int(value, 0)  # auto-detects base (0x or decimal), supports sign
    except ValueError as e:
        raise ValueError(f"envInt parsing failed for {key} = {value}: {e}") from e


def env_uint(key: str, default: str | None = None) -> int:
    value = env_string(key, default=default)
    try:
        result = value if isinstance(value, int) else int(value, 0)
        if result < 0:
            raise ValueError(
                f"envUint parsing failed for {key} = {value}: value must be non-negative"
            )
        return result
    except ValueError as e:
        raise ValueError(f"envUint parsing failed for {key} = {value}: {e}") from e


def env_int_array(key: str, delimiter: str = ",") -> list[int]:
    value = env_string(key)
    parts = [x.strip() for x in value.split(delimiter)]
    try:
        return [int(x, 0) for x in parts]  # base 0 supports hex/dec
    except ValueError as e:
        raise ValueError(f"envIntArray failed to parse: {e}") from e


def env_bool(key: str, default: str | None = None) -> bool:
    value = env_string(key, default=default)
    return value.lower() in ["1", "true", "yes"]


def env_address(key: str, default: str | None = None) -> str:
    value = env_string(key, default=default)
    if not value.startswith("0x") or len(value) != 42:
        raise ValueError(f"Invalid Ethereum address format for {key}: {value}")
    return value.lower()


def env_bytes32(key: str, default: str | None = None) -> str:
    value = env_string(key, default=default)
    if not value.startswith("0x") or len(value) != 66:
        raise ValueError(f"Invalid bytes32 format for {key}: {value}")
    return value.lower()


def env_bytes(key: str, default: str | None = None) -> bytes:
    value = env_string(key, default=default)
    if value.startswith("0x"):
        return bytes.fromhex(value[2:])
    return value.encode()


def env_uint_array(key: str, default: str | None = None, delimiter=",") -> list[int]:
    value = env_string(key, default=default)
    return [int(x.strip()) for x in value.split(delimiter)]


def env_address_array(key: str, default: str | None = None, delimiter=",") -> list[str]:
    value = env_string(key, default=default)
    addresses = [x.strip() for x in value.split(delimiter)]
    for address in addresses:
        if not address.startswith("0x") or len(address) != 42:
            raise ValueError(
                f"Invalid Ethereum address format in array for {key}: {address}"
            )
    return [address.lower() for address in addresses]


def env_bool_array(key: str, default: str | None = None, delimiter=",") -> list[bool]:
    value = env_string(key, default=default)
    bool_array = [x.strip() for x in value.split(delimiter)]
    return [x.lower() in ["1", "true", "yes"] for x in bool_array]


def env_bytes32_array(key: str, default: str | None = None, delimiter=",") -> list[str]:
    value = env_string(key, default=default)
    parts = [x.strip() for x in value.split(delimiter)]
    for part in parts:
        if not part.startswith("0x") or len(part) != 66:
            raise ValueError(f"Invalid bytes32 format in array for {key}: {part}")
    return [part.lower() for part in parts]


def env_string_array(key: str, default: str | None = None, delimiter=",") -> list[str]:
    value = env_string(key, default=default)
    return [x.strip() for x in value.split(delimiter)]


def env_bytes_array(key: str, default: str | None = None, delimiter=",") -> list[bytes]:
    value = env_string(key, default=default)
    return [x.strip() for x in value.split(delimiter)]


def env_or_address(key: str, default: str | None = None) -> str:
    try:
        return env_address(key)
    except ValueError:
        if default is not None:
            return default
        raise ValueError(
            f"Environment variable '{key}' is not set or invalid."
        ) from None


def env_or_bool(key: str, default: bool = False) -> bool:
    try:
        return env_bool(key)
    except ValueError:
        return default


def env_or_bytes(key: str, default: bytes = b"") -> bytes:
    try:
        return env_bytes(key)
    except ValueError:
        return default


def env_or_string(key: str, default: str = "") -> str:
    try:
        return env_string(key)
    except ValueError:
        return default


def env_or_bytes32(key: str, default: str = "") -> str:
    try:
        return env_bytes32(key)
    except ValueError:
        return default


def env_or_int(key: str, default: int | None = None) -> int:
    try:
        return env_int(key)
    except ValueError:
        if default is not None:
            return default
        raise ValueError(
            f"Environment variable '{key}' is not set or invalid."
        ) from None


def env_or_uint(key: str, default: int | None = None) -> int:
    try:
        return env_uint(key)
    except ValueError:
        if default is not None:
            return default
        raise ValueError(
            f"Environment variable '{key}' is not set or invalid."
        ) from None


def env_or_string_address_array(
    key: str, default: list[str] | None = None, delimiter=","
) -> list[str]:
    try:
        return env_address_array(key, delimiter=delimiter)
    except ValueError:
        return default if default is not None else []


def env_or_string_bool_array(
    key: str, default: list[bool] | None = None, delimiter=","
) -> list[bool]:
    try:
        return env_bool_array(key, delimiter=delimiter)
    except ValueError:
        return default if default is not None else []


def env_or_string_bytes32_array(
    key: str, default: list[str] | None = None, delimiter=","
) -> list[str]:
    try:
        return env_bytes32_array(key, delimiter=delimiter)
    except ValueError:
        return default if default is not None else []


def env_or_string_int_array(
    key: str, default: list[int] | None = None, delimiter=","
) -> list[int]:
    try:
        return env_uint_array(key, delimiter=delimiter)
    except ValueError:
        return default if default is not None else []


def env_or_string_uint_array(
    key: str, default: list[int] | None = None, delimiter=","
) -> list[int]:
    try:
        return env_uint_array(key, delimiter=delimiter)
    except ValueError:
        return default if default is not None else []


def env_or_string_bytes_array(
    key: str, default: list[bytes] | None = None, delimiter=","
) -> list[bytes]:
    try:
        return env_bytes_array(key, delimiter=delimiter)
    except ValueError:
        return default if default is not None else []


def env_or_string_string_array(
    key: str, default: list[str] | None = None, delimiter=","
) -> list[str]:
    try:
        return env_string_array(key, delimiter=delimiter)
    except ValueError:
        return default if default is not None else []
