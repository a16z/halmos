import os
import pytest

from halmos.parser import ConfigFileProvider, ConfigParser, Config


def mock_config_file_provider(config_file_contents):
    # use a real object but with a non-existent file and mocked contents
    provider = ConfigFileProvider(config_files=["mock_halmos.toml"])
    provider.config_file_contents = config_file_contents
    return provider


def test_config_file_default_location_is_cwd():
    cfp = ConfigFileProvider()

    # when we don't pass the project root as an argument
    cfp.resolve_config_files(args=[])

    # then the config file should be in the default location
    assert cfp.provide() == [os.path.join(os.getcwd(), "halmos.toml")]


def test_config_file_in_project_root():
    cfp = ConfigFileProvider()

    # when we pass the project root as an argument
    args = ["--root", "/path/to/project", "--extra-args", "ignored", "--help"]
    cfp.resolve_config_files(args)

    # then the config file should be in the project root
    assert cfp.provide() == ["/path/to/project/halmos.toml"]


def test_load_config_file_not_found():
    # when we try to load a non-existent config file
    cfp = ConfigFileProvider(config_files=["nonexistent.toml"])
    config_parser = ConfigParser(config_file_provider=cfp)
    config = config_parser.parse_config(args="")

    # then we should get a config object with default values
    assert "Config File" not in config.format_values()


def test_load_config_file_missing_section():
    # mock a valid config file with a missing section
    cfp = mock_config_file_provider("depth = 42")
    config_parser = ConfigParser(config_file_provider=cfp)

    # when we parse the config with the missing section
    config = config_parser.parse_config(args="")

    # then the malformed config file does not contribute to the config object
    assert "Config File" not in config.format_values()
    assert config.depth != 42


def test_parse_config_invalid_key():
    # mock a valid config file with an invalid key
    cfp = mock_config_file_provider("[global]\ninvalid_key = 42")
    config_parser = ConfigParser(config_file_provider=cfp)

    # invalid keys result in an error and exit
    with pytest.raises(SystemExit) as exc_info:
        config_parser.parse_config(args="")
    assert exc_info.value.code == 2


def test_parse_config_invalid_type():
    cfp = mock_config_file_provider("[global]\ndepth = 'invalid'")
    config_parser = ConfigParser(config_file_provider=cfp)

    # invalid types result in an error and exit
    with pytest.raises(SystemExit) as exc_info:
        config_parser.parse_config(args="")
    assert exc_info.value.code == 2


def test_parse_config_success():
    # mock a valid config file
    cfp = mock_config_file_provider("[global]\ndepth = 42")
    config_parser = ConfigParser(config_file_provider=cfp)

    # when we parse the config
    config = config_parser.parse_config(args="")

    # then we should get a config object with the correct values
    assert config.depth == 42


def test_parse_config_override():
    # mock a valid config file
    cfp = mock_config_file_provider("[global]\ndepth = 42\nverbose = 1234")
    config_parser = ConfigParser(config_file_provider=cfp)

    # when we parse the config with an override
    config = config_parser.parse_config(args="--depth 123456")

    # then we should get a config object with the overridden value
    assert config.depth == 123456

    # from config file
    assert config.verbose == 1234

    # from command line defaults
    assert config.loop == 2


def test_config_extend_does_not_modify_original():
    # mock a valid config file
    cfp = mock_config_file_provider("[global]\ndepth = 42\nverbose = 1234")
    config_parser = ConfigParser(config_file_provider=cfp)
    config = config_parser.parse_config(args="")
    assert config.depth == 42

    # when we extend the config
    new_config = config.extend("--depth=123456")

    # then the new config should have the overridden value
    assert new_config.depth == 123456

    # and the original config should not be modified
    assert config.depth == 42
