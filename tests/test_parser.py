import argparse
from unittest.mock import mock_open, patch

import pytest

from halmos.parser import load_config_file, parse_config


@pytest.fixture
def mock_config():
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
    args.config = "halmos.toml"
    args.depth = None
    args.array_lengths = None
    return args


def test_load_config_file_not_found(monkeypatch):
    monkeypatch.setattr("os.path.exists", lambda x: False)
    assert load_config_file("not_exist.toml") is None


def test_parse_config_success(mock_config, mock_parser, mock_args):
    updated_args = parse_config(mock_config, mock_parser, mock_args, [])
    assert updated_args.depth == 4
    assert updated_args.array_lengths == 2


def test_parse_config_invalid_key(mock_parser, mock_args):
    invalid_key_config = {
        "settings": {
            "invalid_key": "invalid",
        }
    }
    updated_args = parse_config(invalid_key_config, mock_parser, mock_args, [])
    assert not hasattr(updated_args, "invalid_key")


def test_parse_config_invalid_type(mock_parser, mock_args):
    invalid_type_config = {
        "settings": {
            "depth": "invalid",
            "array-lengths": 2,
        }
    }
    updated_args = parse_config(invalid_type_config, mock_parser, mock_args, [])
    assert updated_args.depth is None
    assert updated_args.array_lengths == 2


def test_parse_config_skip_in_commands(mock_config, mock_parser, mock_args):
    mock_args.depth = 5
    updated_args = parse_config(mock_config, mock_parser, mock_args, ["--depth", "5"])

    assert updated_args.depth == 5
    assert updated_args.array_lengths == 2
