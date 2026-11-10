# SPDX-License-Identifier: AGPL-3.0

"""
Filesystem access for the file cheatcodes (vm.readFile, vm.readFileBinary, ...).

Access is governed by the project's `fs_permissions`, with the same semantics as
Foundry, so that a test reading a file behaves identically under `forge test` and
under dolmos:

- permissions are read from the resolved forge configuration (`forge config --json`),
  so profiles and environment overrides are honored;
- paths, both requested and permitted, are resolved against the project root and
  normalized lexically (`a/../b` becomes `b`; symlinks are not followed);
- the most specific permission (longest matching path) wins, so a nested
  `{ access = "none", path = "./data/private" }` overrides a broader read grant;
- without any matching permission, access is denied.
"""

import json
import os
import re
import subprocess
from dataclasses import dataclass
from functools import cache

from dolmos.exceptions import DolmosException
from dolmos.logs import debug, warn

# foundry's default when fs_permissions is not configured
DEFAULT_FS_PERMISSIONS: tuple[dict, ...] = ({"access": "read", "path": "out"},)

# `forge config --json` serializes "read-write" as true and "none" as false
_ACCESS_ALIASES = {
    True: "read-write",
    False: "none",
    "true": "read-write",
    "false": "none",
}

_READABLE = frozenset({"read", "read-write"})


@dataclass(frozen=True)
class FsPermission:
    access: str  # "none" | "read" | "write" | "read-write"
    path: str  # absolute and normalized

    @property
    def can_read(self) -> bool:
        return self.access in _READABLE


def resolve_path(root: str, path: str) -> str:
    """Absolute, lexically normalized path; relative paths are taken from root."""
    return os.path.normpath(os.path.join(os.path.abspath(root), path))


def parse_fs_permissions(root: str, raw: list | tuple) -> tuple[FsPermission, ...]:
    permissions = []
    for entry in raw:
        access = entry["access"]
        access = _ACCESS_ALIASES.get(access, access)
        if isinstance(access, str):
            access = access.lower()
        permissions.append(FsPermission(access, resolve_path(root, entry["path"])))
    return tuple(permissions)


@cache
def load_fs_permissions(root: str) -> tuple[FsPermission, ...]:
    """Resolved fs_permissions of the forge project at root (cached per root)."""

    cmd = ["forge", "config", "--json", "--root", root]
    try:
        # forge writes utf-8 (warnings may contain non-ascii): do not decode with the
        # locale encoding, which is not utf-8 on Windows
        result = subprocess.run(
            cmd,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            check=True,
        )
        raw = json.loads(result.stdout).get("fs_permissions") or []
    except (OSError, subprocess.CalledProcessError, ValueError) as e:
        warn(
            f"could not resolve fs_permissions with `{' '.join(cmd)}` ({e}); "
            "falling back to foundry's default (read access to `out` only)"
        )
        raw = DEFAULT_FS_PERMISSIONS

    permissions = parse_fs_permissions(root, raw)
    debug(f"fs_permissions for {root}: {permissions}")
    return permissions


def find_permission(
    permissions: tuple[FsPermission, ...], abs_path: str
) -> FsPermission | None:
    """The most specific permission covering abs_path, if any."""

    # paths are case-insensitive on Windows (normcase is the identity elsewhere)
    target = os.path.normcase(abs_path)
    best = None
    for permission in permissions:
        base = os.path.normcase(permission.path)
        covered = target == base or target.startswith(base.rstrip(os.sep) + os.sep)
        if covered and (best is None or len(permission.path) > len(best.path)):
            best = permission
    return best


def ensure_readable(
    root: str,
    path: str,
    cheatcode: str,
    permissions: tuple[FsPermission, ...] | None = None,
) -> str:
    """
    Returns the absolute path to read, or raises if fs_permissions deny reading it.
    """

    if permissions is None:
        permissions = load_fs_permissions(root)

    abs_path = resolve_path(root, path)
    permission = find_permission(permissions, abs_path)
    if permission is None or not permission.can_read:
        shown = os.path.relpath(abs_path, os.path.abspath(root))
        if shown.startswith(os.pardir):
            shown = abs_path
        raise DolmosException(
            f"{cheatcode}: the path {shown} is not allowed to be accessed for read "
            "operations (see fs_permissions in foundry.toml)"
        )

    return abs_path


def read_file(root: str, path: str, cheatcode: str) -> bytes:
    """Raw content of the file at path, subject to fs_permissions."""

    abs_path = ensure_readable(root, path, cheatcode)
    try:
        with open(abs_path, "rb") as f:
            return f.read()
    except OSError as e:
        raise DolmosException(f"{cheatcode}: failed to read {abs_path}: {e}") from e


_HEX_DIGITS = re.compile(r"[0-9a-fA-F]*")


def parse_hex_bytes(value: str, cheatcode: str = "vm.parseBytes") -> bytes:
    """
    Parses a hex string the way Foundry's vm.parseBytes does: an optional
    lowercase `0x` prefix followed by an even number of hex digits. Whitespace
    is rejected, and the empty string is only accepted as `0x`.
    """

    digits = value[2:] if value.startswith("0x") else value

    if not value:
        reason = 'missing hex prefix ("0x") for hex string'
    elif not _HEX_DIGITS.fullmatch(digits):
        reason = "invalid hex character"
    elif len(digits) % 2:
        reason = "odd number of digits"
    else:
        return bytes.fromhex(digits)

    raise DolmosException(f'{cheatcode}: failed parsing "{value}" as bytes: {reason}')
