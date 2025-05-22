# halmos/cheatcodes/env.py

import os

from dotenv import load_dotenv

load_dotenv()  # Load environment variables from .env file


class Env:
    def _key(self, key: str) -> str:
        return key  # You can add prefix handling here if needed

    def _parse_env_var(self, key: str, default=None):
        value = os.getenv(self._key(key), default)
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
