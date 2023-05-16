import pytest

from halmos.sevm import SEVM

from halmos.__main__ import parse_args, mk_options

@pytest.fixture
def args():
    (args, unknown_args) = parse_args([])
    return args

@pytest.fixture
def options(args):
    return mk_options(args)

@pytest.fixture
def sevm(options):
    return SEVM(options)
