import argparse
from unittest.mock import mock_open, patch

import pytest

from halmos.parser import load_configure_file, parse_configure_file


@pytest.fixture
def mock_configure():
    return {
        "settings": {
            "depth": 4,
            "array-lengths": 2,
        }
    }


@pytest.fixture
def mock_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument("--depth", type=int)
    parser.add_argument("--array-lengths")
    return parser


@pytest.fixture
def mock_args():
    args = argparse.Namespace()
    args.root = "/fake/path"
    args.configure = "halmos.toml"
    args.depth = None
    args.array_lengths = None
    return args


@pytest.fixture
def patchs(monkeypatch, mock_configure):
    monkeypatch.setattr("os.path.exists", lambda path: True)
    monkeypatch.setattr("builtins.open", mock_open())
    monkeypatch.setattr("toml.load", lambda f: mock_configure)


def test_load_configure_file_not_found(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda x: False)

    assert load_configure_file("not_exist.toml") is None


def test_load_configure_file_exist(patchs, mock_configure):
    assert load_configure_file("test.toml") == mock_configure


def test_parse_configure_file_success(patchs, mock_parser, mock_args):
    updated_args = parse_configure_file(mock_parser, mock_args, [])
    assert updated_args.depth == 4
    assert updated_args.array_lengths == 2


def test_parse_configure_file_not_found_file(monkeypatch, mock_parser, mock_args):
    monkeypatch.setattr("os.path.exists", lambda x: False)
    updated_args = parse_configure_file(mock_parser, mock_args, [])
    assert updated_args.depth is None
    assert updated_args.array_lengths is None


def test_parse_configure_file_invalid_key(monkeypatch, patchs, mock_parser, mock_args):
    monkeypatch.setattr(
        "toml.load",
        lambda f: {
            "settings": {
                "invalid_key": "invalid",
            }
        },
    )
    updated_args = parse_configure_file(mock_parser, mock_args, [])
    assert not hasattr(updated_args, "invalid_key")


def test_parse_configure_file_invalid_type(monkeypatch, patchs, mock_parser, mock_args):
    monkeypatch.setattr(
        "toml.load",
        lambda f: {
            "settings": {
                "depth": "invalid",
                "array-lengths": 2,
            }
        },
    )
    updated_args = parse_configure_file(mock_parser, mock_args, [])
    assert updated_args.depth is None
    assert updated_args.array_lengths == 2


def test_parse_confiure_file_skip_in_commands(patchs, mock_parser, mock_args):
    mock_args.depth = 5
    updated_args = parse_configure_file(mock_parser, mock_args, ["--depth", "5"])

    assert updated_args.depth == 5
    assert updated_args.array_lengths == 2
