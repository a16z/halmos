# halmos/cheatcodes/env.py

import os

from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file


class Env:
    def _key(self, key: str) -> str:
        return key  # You can add prefix handling here if needed

    def _parse_env_var(self, key: str, default=None):
        value = os.getenv(self._key(key), default)
        print(f"Parsing environment variable: {key} = {value}")
        if value is None:
            raise ValueError(
                f"Environment variable '{key}' is not set and no default provided."
            )
        return value

    def _parse_int(self, key: str, default=None) -> int:
        return int(self._parse_env_var(key, default))

    def _parse_bool(self, key: str, default=None) -> bool:
        val = self._parse_env_var(key, default).lower()
        return val in ["1", "true", "yes"]

    def _parse_address(self, key: str, default=None) -> str:
        val = self._parse_env_var(key, default)
        if not val.startswith("0x") or len(val) != 42:
            raise ValueError(f"Invalid Ethereum address format for {key}: {val}")
        return val.lower()

    def _parse_bytes32(self, key: str, default=None) -> str:
        val = self._parse_env_var(key, default)
        if not val.startswith("0x") or len(val) != 66:
            raise ValueError(f"Invalid bytes32 format for {key}: {val}")
        return val.lower()

    def _parse_bytes(self, key: str, default=None) -> bytes:
        val = self._parse_env_var(key, default)
        if val.startswith("0x"):
            return bytes.fromhex(val[2:])
        return val.encode()

    def _parse_uint_array(self, key: str, default=None, delimiter=",") -> list[int]:
        val = self._parse_env_var(key, default)
        return [int(x.strip()) for x in val.split(delimiter)]

    def _parse_address_array(self, key: str, default=None, delimiter=",") -> list[str]:
        val = self._parse_env_var(key, default)
        addresses = [x.strip() for x in val.split(delimiter)]
        for address in addresses:
            if not address.startswith("0x") or len(address) != 42:
                raise ValueError(
                    f"Invalid Ethereum address format in array for {key}: {address}"
                )
        return [address.lower() for address in addresses]

    def _parse_bool_array(self, key: str, default=None, delimiter=",") -> list[bool]:
        val = self._parse_env_var(key, default)
        bool_array = [(x.strip()) for x in val.split(delimiter)]
        return [x.lower() in ["1", "true", "yes"] for x in bool_array]

    def _parse_bytes32_array(self, key: str, default=None, delimiter=",") -> list[str]:
        val = self._parse_env_var(key, default)
        parts = [x.strip() for x in val.split(delimiter)]
        for part in parts:
            if not part.startswith("0x") or len(part) != 66:
                raise ValueError(f"Invalid bytes32 format in array for {key}: {part}")
        return [part.lower() for part in parts]

    def _parse_string_array(self, key: str, default=None, delimiter=",") -> list[str]:
        val = self._parse_env_var(key, default)
        return [x.strip() for x in val.split(delimiter)]

    def _parse_bytes_array(self, key: str, default=None, delimiter=",") -> list[bytes]:
        val = self._parse_env_var(key, default)
        return [x.strip() for x in val.split(delimiter)]

    # Reusable API
    def env_string(self, key: str, default: str = None) -> str:
        return self._parse_env_var(key, default)

    def env_int(self, key: str, default: str = None) -> int:
        val = self._parse_env_var(key)  # raises if missing
        try:
            return int(val, 0)  # auto-detects base (0x or decimal), supports sign
        except ValueError as e:
            raise ValueError(f"envInt parsing failed for {key} = {val}: {e}") from e

    def env_uint(self, key: str, default: str = None) -> int:
        val = self._parse_env_var(key, default)
        try:
            result = int(val, 0)
            if result < 0:
                raise ValueError(
                    f"envUint parsing failed for {key} = {val}: value must be non-negative"
                )
            return result
        except ValueError as e:
            raise ValueError(f"envUint parsing failed for {key} = {val}: {e}") from e

    def env_int_array(self, key: str, delimiter: str = ",") -> list[int]:
        raw = self._parse_env_var(key)
        parts = [x.strip() for x in raw.split(delimiter)]
        try:
            return [int(x, 0) for x in parts]  # base 0 supports hex/dec
        except ValueError as e:
            raise ValueError(f"envIntArray failed to parse: {e}") from e

    def env_bool(self, key: str, default: str = None) -> bool:
        return self._parse_bool(key, default)

    def env_address(self, key: str, default: str = None) -> str:
        return self._parse_address(key, default)

    def env_bytes32(self, key: str, default: str = None) -> str:
        return self._parse_bytes32(key, default)

    def env_bytes(self, key: str, default: str = None) -> bytes:
        return self._parse_bytes(key, default)

    def env_uint_array(self, key: str, default: str = None, delimiter=",") -> list[int]:
        return self._parse_uint_array(key, default, delimiter)

    def env_address_array(
        self, key: str, default: str = None, delimiter=","
    ) -> list[str]:
        return self._parse_address_array(key, default, delimiter)

    def env_bool_array(
        self, key: str, default: str = None, delimiter=","
    ) -> list[bool]:
        return self._parse_bool_array(key, default, delimiter)

    def env_bytes32_array(
        self, key: str, default: str = None, delimiter=","
    ) -> list[str]:
        return self._parse_bytes32_array(key, default, delimiter)

    def env_string_array(
        self, key: str, default: str = None, delimiter=","
    ) -> list[str]:
        return self._parse_string_array(key, default, delimiter)

    def env_bytes_array(
        self, key: str, default: str = None, delimiter=","
    ) -> list[bytes]:
        return self._parse_bytes_array(key, default, delimiter)
