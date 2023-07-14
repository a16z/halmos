import pytest

from halmos.sevm import SEVM

from halmos.__main__ import parse_args, mk_options
import halmos.__main__

@pytest.fixture
def args():
    args = parse_args([])

    # set the global args for the main module
    halmos.__main__.args = args

    return args

@pytest.fixture
def options(args):
    return mk_options(args)

@pytest.fixture
def sevm(options):
    return SEVM(options)
