import dataclasses
import os
import pickle

import pytest

from halmos.config import (
    Config,
    ConfigSource,
    ParseArrayLengths,
    ParseCSVInt,
    ParseErrorCodes,
    arg_parser,
    default_config,
    resolve_config_files,
)
from halmos.config import (
    toml_parser as get_toml_parser,
)

void = ConfigSource.void


@pytest.fixture
def void_config():
    return Config(_parent=None, _source=void)


@pytest.fixture
def config():
    return default_config()


@pytest.fixture
def parser():
    return arg_parser()


@pytest.fixture
def toml_parser():
    return get_toml_parser()


def test_fresh_config_has_only_None_values(void_config):
    for field in void_config.__dataclass_fields__.values():
        if field.metadata.get("internal"):
            continue
        assert getattr(void_config, field.name) is None


def test_default_config_immutable(config):
    with pytest.raises(dataclasses.FrozenInstanceError):
        config.solver_threads = 42


def test_unknown_keys_config_constructor_raise():
    with pytest.raises(TypeError):
        Config(_parent=None, _source=void, unknown_key=42)


def test_unknown_keys_config_object_raise(void_config):
    with pytest.raises(AttributeError):
        void_config.unknown_key  # noqa: B018 (not a useless expression)


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

    override = config.with_overrides(ConfigSource.command_line, verbose=42)

    # # the override is reflected in the new config
    assert override.verbose == 42

    # # the default config is unchanged
    assert config.verbose == verbose_before

    # default values are still available in the override config
    assert override.solver_threads == config.solver_threads


def test_toml_parser_expects_single_section(toml_parser):
    # extra section
    with pytest.raises(SystemExit):
        toml_parser.parse_str("[global]\na = 1\n[extra]\nb = 2")

    # missing global
    with pytest.raises(SystemExit):
        toml_parser.parse_str("a = 1\nb = 2")

    # single section is not expected one
    with pytest.raises(SystemExit):
        toml_parser.parse_str("[weird]\na = 1\nb = 2")

    # works
    toml_parser.parse_str("[global]")


def test_config_file_default_location_is_cwd():
    # when we don't pass the project root as an argument
    config_files = resolve_config_files(args=[])

    # then we don't expect a config file since the default doesn't exist
    assert config_files == []


def test_config_file_in_project_root():
    # when we pass the project root as an argument
    base_path = "/path/to/project"
    args = ["--root", base_path, "--extra-args", "ignored"]
    config_files = resolve_config_files(args, include_missing=True)

    # then the config file should be in the project root
    assert config_files == [os.path.join(base_path, "halmos.toml")]


def test_config_file_explicit():
    # when we pass a --config argument explicitly
    args = ["--config", "path/to/fake.toml", "--extra-args", "ignored"]
    config_files = resolve_config_files(args)

    # then we expect the config file to be the one we passed
    assert config_files == ["path/to/fake.toml"]


def test_config_file_invalid_key(config, toml_parser):
    # invalid keys result in an error and exit
    with pytest.raises(SystemExit) as exc_info:
        data = toml_parser.parse_str("[global]\ninvalid_key = 42")
        config = config.with_overrides(ConfigSource.config_file, **data)
    assert exc_info.value.code == 2


# TODO: uncomment when type checking is implemented
# def test_config_file_invalid_type(toml_parser):
#     # invalid types result in an error and exit
#     with pytest.raises(SystemExit) as exc_info:
#         config = toml_parser.parse_str("[global]\ndepth = 'invalid'")
#         print(config)
#     assert exc_info.value.code == 2


def test_config_file_snake_case(config, toml_parser):
    config_file_data = toml_parser.parse_str("[global]\nsolver-threads = 42")
    assert config_file_data["solver_threads"] == 42

    config = config.with_overrides(ConfigSource.config_file, **config_file_data)
    assert config.solver_threads == 42


def test_config_e2e(config, parser, toml_parser):
    # when we apply overrides to the default config
    config_file_data = toml_parser.parse_str("[global]\nverbose = 42")
    config = config.with_overrides(ConfigSource.config_file, **config_file_data)

    args = parser.parse_args(["-vvv"])
    config = config.with_overrides(ConfigSource.command_line, **vars(args))

    # then the config object should have the expected values
    assert config.verbose == 3
    assert config.loop == 2

    # and each value should have the expected source
    assert config.value_with_source("verbose") == (3, ConfigSource.command_line)
    assert config.value_with_source("loop") == (2, ConfigSource.default)


def test_config_pickle(config, parser):
    args = parser.parse_args(["-vvv"])
    config = config.with_overrides(ConfigSource.command_line, **vars(args))

    # pickle and unpickle the config
    pickled = pickle.dumps(config)
    unpickled = pickle.loads(pickled)

    # then the config object should be the same
    assert config == unpickled
    assert unpickled.value_with_source("verbose") == (3, ConfigSource.command_line)


def test_parse_csv():
    with pytest.raises(ValueError):
        ParseCSVInt.parse("")
        ParseCSVInt.parse(" ")
        ParseCSVInt.parse(",")
    assert ParseCSVInt.parse("0") == [0]
    assert ParseCSVInt.parse("0,") == [0]
    assert ParseCSVInt.parse("1,2,3") == [1, 2, 3]
    assert ParseCSVInt.parse("1,2,3,") == [1, 2, 3]
    assert ParseCSVInt.parse(" 1 , 2 , 3 ") == [1, 2, 3]
    assert ParseCSVInt.parse(" , 1 , 2 , 3 , ") == [1, 2, 3]


def test_unparse_csv():
    assert ParseCSVInt.unparse([]) == ""
    assert ParseCSVInt.unparse([0]) == "0"
    assert ParseCSVInt.unparse([1, 2, 3]) == "1,2,3"


def test_parse_csv_roundtrip():
    test_cases = [
        [0],
        [1, 2, 3],
    ]

    for original in test_cases:
        unparsed = ParseCSVInt.unparse(original)
        parsed = ParseCSVInt.parse(unparsed)
        assert parsed == original, f"Roundtrip failed for {original}"


def test_parse_error_codes():
    with pytest.raises(ValueError):
        ParseErrorCodes.parse("")
        ParseErrorCodes.parse(" ")
        ParseErrorCodes.parse(",")
        ParseErrorCodes.parse("1,*")
        ParseErrorCodes.parse(",*")
        ParseErrorCodes.parse("*,")
    assert ParseErrorCodes.parse("*") == set()
    assert ParseErrorCodes.parse(" * ") == set()
    assert ParseErrorCodes.parse("0") == {0}
    assert ParseErrorCodes.parse("0,") == {0}
    assert ParseErrorCodes.parse("1,2,3") == {1, 2, 3}
    assert ParseErrorCodes.parse("1,2,3,") == {1, 2, 3}
    assert ParseErrorCodes.parse(" 1 , 2 , 3 ") == {1, 2, 3}
    assert ParseErrorCodes.parse(" , 1 , 2 , 3 , ") == {1, 2, 3}
    assert ParseErrorCodes.parse(" 0b10 , 0o10 , 10, 0x10 ") == {2, 8, 10, 16}


def test_unparse_error_codes():
    assert ParseErrorCodes.unparse(set()) == "*"
    assert ParseErrorCodes.unparse({0}) == "0x00"
    assert ParseErrorCodes.unparse({1, 2}) in {"0x01,0x02", "0x02,0x01"}


def test_parse_error_codes_roundtrip():
    test_cases = [
        set(),
        {0},
        {1, 2},
        {1, 2, 3},
    ]

    for original in test_cases:
        unparsed = ParseErrorCodes.unparse(original)
        parsed = ParseErrorCodes.parse(unparsed)
        assert parsed == original, f"Roundtrip failed for {original}"


def test_parse_array_lengths():
    with pytest.raises(ValueError):
        # advancing commas not allowed
        ParseArrayLengths.parse(",")
        ParseArrayLengths.parse(",x=1")
        # empty sizes not allowed
        ParseArrayLengths.parse("x=")
        ParseArrayLengths.parse("x={}")
        # invalid names
        ParseArrayLengths.parse("x{0}=1")
    assert ParseArrayLengths.parse("") == {}
    assert ParseArrayLengths.parse(" ") == {}
    assert ParseArrayLengths.parse("x=1") == {"x": [1]}
    # arbitrary expressions are allowed for names
    assert ParseArrayLengths.parse("x[0]=1") == {"x[0]": [1]}
    # trailing commas are allowed
    assert ParseArrayLengths.parse("x=1,") == {"x": [1]}
    assert ParseArrayLengths.parse("x={1,2},y=3") == {"x": [1, 2], "y": [3]}
    assert ParseArrayLengths.parse("x={1,2,},y=3") == {"x": [1, 2], "y": [3]}
    assert ParseArrayLengths.parse("x={1,2},y={3,}") == {"x": [1, 2], "y": [3]}
    assert ParseArrayLengths.parse("x={1,2},y=3,") == {"x": [1, 2], "y": [3]}
    assert ParseArrayLengths.parse("x={1,2,},y={3,},") == {"x": [1, 2], "y": [3]}
    assert ParseArrayLengths.parse(" x = { 1 , 2 } , y = 3 ") == {"x": [1, 2], "y": [3]}
    assert ParseArrayLengths.parse(" x = { 1 , 2 } , y = 3 , ") == {
        "x": [1, 2],
        "y": [3],
    }
    assert ParseArrayLengths.parse(" x = { , 1 , 2 , } , y = { , 3 , } , ") == {
        "x": [1, 2],
        "y": [3],
    }


def test_unparse_array_lengths():
    assert ParseArrayLengths.unparse({}) == ""
    assert ParseArrayLengths.unparse({"x": [1]}) == "x={1}"
    assert ParseArrayLengths.unparse({"x": [1, 2], "y": [3]}) in {
        "x={1,2},y={3}",
        "y={3},x={1,2}",
    }


def test_parse_array_lengths_roundtrip():
    test_cases = [
        {},
        {"x": [1]},
        {"x": [1, 2], "y": [3]},
        {"x": [1, 2, 3], "y": [4, 5], "z": [6]},
    ]

    for original in test_cases:
        unparsed = ParseArrayLengths.unparse(original)
        parsed = ParseArrayLengths.parse(unparsed)
        assert parsed == original, f"Roundtrip failed for {original}"


def test_value_with_source(config):
    assert config.value_with_source("solver_threads") == (
        config.solver_threads,
        ConfigSource.default,
    )

    overrides = {"solver_threads": 42}

    config_from_args = config.with_overrides(
        source=ConfigSource.command_line, **overrides
    )

    val, source = config_from_args.value_with_source("solver_threads")
    assert val == 42
    assert source == ConfigSource.command_line

    # overrides have higher precedence than defaults
    assert source > ConfigSource.default


def test_solver_resolution_precedence(config):
    # default config
    assert config.solver == "yices"
    assert config.solver_command == ""

    # the resolved solver command is derived from the default solver
    assert "yices" in " ".join(config.resolved_solver_command)

    #########################################################
    # command line overrides
    #########################################################

    cli_config = config.with_overrides(ConfigSource.command_line, solver="cvc5")
    assert cli_config.solver == "cvc5"

    # the solver command is inherited from the default config
    assert cli_config.solver_command == config.solver_command

    # but the actual command is derived from the solver option (at a higher precedence)
    assert "cvc5" in " ".join(cli_config.resolved_solver_command)

    #########################################################
    # contract annotation overrides
    #########################################################

    contract_config = cli_config.with_overrides(
        ConfigSource.contract_annotation,
        solver_command="path/to/bitwuzla --produce-models",
    )
    # the solver option is inherited from the command line config
    assert contract_config.value_with_source("solver") == (
        "cvc5",
        ConfigSource.command_line,
    )

    # the solver command comes from the contract annotation
    assert contract_config.solver_command == "path/to/bitwuzla --produce-models"

    # the resolved solver command is derived from the contract annotation
    assert contract_config.resolved_solver_command == [
        "path/to/bitwuzla",
        "--produce-models",
    ]
