import os
import subprocess

import pytest

from dolmos import fs
from dolmos.exceptions import DolmosException
from dolmos.fs import (
    FsPermission,
    ensure_readable,
    find_permission,
    parse_fs_permissions,
    parse_hex_bytes,
    resolve_path,
)

ROOT = "/project"


def P(path: str) -> str:
    """
    The absolute, normalized form of a POSIX-style test path on the current OS
    (on Windows, '/project/a' is D:\\project\\a, as returned by resolve_path).
    """
    return os.path.normpath(os.path.abspath(path))


def perms(*entries) -> tuple[FsPermission, ...]:
    return parse_fs_permissions(ROOT, [{"access": a, "path": p} for a, p in entries])


def test_parse_fs_permissions_access_aliases():
    # `forge config --json` serializes "read-write" as true and "none" as false
    parsed = perms(("read", "./a"), (True, "b"), (False, "c"), ("write", "/abs/d"))
    assert [(p.access, p.path) for p in parsed] == [
        ("read", P("/project/a")),
        ("read-write", P("/project/b")),
        ("none", P("/project/c")),
        ("write", P("/abs/d")),
    ]
    assert [p.can_read for p in parsed] == [True, True, False, False]


def test_resolve_path_is_lexical():
    assert resolve_path(ROOT, "data/../secret/s.txt") == P("/project/secret/s.txt")
    assert resolve_path(ROOT, "./data/x") == P("/project/data/x")
    assert resolve_path(ROOT, "/elsewhere/x") == P("/elsewhere/x")
    assert resolve_path(ROOT, "../x") == P("/x")


def test_find_permission_most_specific_wins():
    p = perms(("read", "./data"), ("none", "./data/private"))
    assert find_permission(p, P("/project/data/x.txt")).access == "read"
    assert find_permission(p, P("/project/data/private/x.txt")).access == "none"
    assert find_permission(p, P("/project/data/private")).access == "none"
    # order of declaration does not matter
    p = perms(("none", "./data/private"), ("read", "./data"))
    assert find_permission(p, P("/project/data/private/x.txt")).access == "none"


def test_find_permission_matches_path_components_only():
    p = perms(("read", "./data"))
    assert find_permission(p, P("/project/database.txt")) is None
    assert find_permission(p, P("/project/data-other/x")) is None
    assert find_permission(p, P("/project/data")) is not None


def test_find_permission_root():
    p = perms(("read", "./"))
    assert find_permission(p, P("/project/anything/at/all")).access == "read"
    assert find_permission(p, P("/outside")) is None


@pytest.mark.skipif(
    os.name != "nt", reason="paths are case-insensitive on Windows only"
)
def test_find_permission_case_insensitive_on_windows():
    p = perms(("read", "./Data"))
    assert find_permission(p, P("/PROJECT/data/x.txt")).access == "read"


@pytest.mark.parametrize(
    "path",
    [
        "foundry.toml",
        "data/../foundry.toml",
        "data/private/secret.txt",
        "../outside.txt",
        "/etc/passwd",
        "out-of-tree/data/x",
    ],
)
def test_ensure_readable_denied(path):
    p = perms(("read", "./data"), ("none", "./data/private"))
    with pytest.raises(DolmosException, match="not allowed to be accessed"):
        ensure_readable(ROOT, path, "vm.readFile", p)


def test_ensure_readable_allowed():
    p = perms(("read", "./data"), ("read-write", "/shared"), ("write", "./logs"))
    assert ensure_readable(ROOT, "data/x", "vm.readFile", p) == P("/project/data/x")
    assert ensure_readable(ROOT, "/shared/y", "vm.readFile", p) == P("/shared/y")
    with pytest.raises(DolmosException):
        ensure_readable(ROOT, "logs/z", "vm.readFile", p)


def test_ensure_readable_no_permissions():
    with pytest.raises(DolmosException):
        ensure_readable(ROOT, "anything", "vm.readFile", ())


def test_load_fs_permissions_falls_back_to_foundry_default(monkeypatch, tmp_path):
    def failing_run(*args, **kwargs):
        raise FileNotFoundError("forge")

    monkeypatch.setattr(subprocess, "run", failing_run)
    fs.load_fs_permissions.cache_clear()
    try:
        root = str(tmp_path)
        assert fs.load_fs_permissions(root) == (
            FsPermission("read", os.path.join(root, "out")),
        )
    finally:
        fs.load_fs_permissions.cache_clear()


def test_read_file(monkeypatch, tmp_path):
    (tmp_path / "data").mkdir()
    (tmp_path / "data" / "crlf.txt").write_bytes(b"a\r\nb\n")
    (tmp_path / "secret.txt").write_bytes(b"secret")

    root = str(tmp_path)
    monkeypatch.setattr(
        fs,
        "load_fs_permissions",
        lambda r: parse_fs_permissions(r, [{"access": "read", "path": "data"}]),
    )

    # returned as is, no newline translation
    assert fs.read_file(root, "data/crlf.txt", "vm.readFile") == b"a\r\nb\n"

    with pytest.raises(DolmosException, match="failed to read"):
        fs.read_file(root, "data/missing.txt", "vm.readFile")

    with pytest.raises(DolmosException, match="failed to read"):
        fs.read_file(root, "data", "vm.readFile")  # a directory

    with pytest.raises(DolmosException, match="not allowed"):
        fs.read_file(root, "secret.txt", "vm.readFile")


@pytest.mark.parametrize(
    "value, expected",
    [
        ("0x", b""),
        ("0x00ff", b"\x00\xff"),
        ("00ff", b"\x00\xff"),
        ("0xABcd", b"\xab\xcd"),
        ("0x600a600c600039600a6000f3", bytes.fromhex("600a600c600039600a6000f3")),
    ],
)
def test_parse_hex_bytes(value, expected):
    assert parse_hex_bytes(value) == expected


@pytest.mark.parametrize(
    "value, reason",
    [
        ("", "missing hex prefix"),
        ("0x123", "odd number of digits"),
        ("0x6001\n", "invalid hex character"),
        (" 0xab", "invalid hex character"),
        ("0x ab", "invalid hex character"),
        ("0XAB", "invalid hex character"),
        ("0xzz", "invalid hex character"),
    ],
)
def test_parse_hex_bytes_invalid(value, reason):
    with pytest.raises(DolmosException, match=reason):
        parse_hex_bytes(value)
