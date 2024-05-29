import argparse
import pytest

from halmos.config import Config, default_config, arg_parser


@pytest.fixture
def config():
    return default_config()


@pytest.fixture
def parser():
    return arg_parser()


def test_fresh_config_has_only_None_values():
    config = Config(config_parent=None, config_source="bogus")
    for field in config.__dataclass_fields__.values():
        if field.metadata.get("internal"):
            continue
        assert getattr(config, field.name) is None


def test_default_config_immutable(config):
    with pytest.raises(Exception):
        config.solver_threads = 42


def test_unknown_keys_config_constructor_raise():
    with pytest.raises(TypeError):
        Config(config_parent=None, config_source="bogus", unknown_key=42)


def test_unknown_keys_config_object_raise():
    config = Config(config_parent=None, config_source="bogus")
    with pytest.raises(AttributeError):
        config.unknown_key


def test_count_arg(config, parser):
    args = parser.parse_args(["-vvvvvv"])
    assert args.verbose == 6

    config_from_args = config.with_overrides(source="command-line", **vars(args))
    assert config_from_args.verbose == 6


def test_choice_arg(config, parser):
    # wrong choice raises
    with pytest.raises(SystemExit):
        parser.parse_args(["--storage-layout", "beepboop"])

    # valid choice works
    args = parser.parse_args(["--storage-layout", "generic"])
    overrides = config.with_overrides(source="command-line", **vars(args))
    assert overrides.storage_layout == "generic"


def test_override(config):
    verbose_before = config.verbose

    override = Config(config_parent=config, config_source="override", verbose=42)

    # # the override is reflected in the new config
    assert override.verbose == 42

    # # the default config is unchanged
    assert config.verbose == verbose_before

    # default values are still available in the override config
    assert override.solver_threads == config.solver_threads
