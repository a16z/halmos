import pytest

from halmos.sevm import SEVM

from halmos.__main__ import arg_parser, mk_options
import halmos.__main__


@pytest.fixture
def args():
    args = arg_parser.parse_args([])

    # set the global args for the main module
    halmos.__main__.args = args

    return args


@pytest.fixture
def options(args):
    return mk_options(args)


@pytest.fixture
def sevm(options):
    return SEVM(options)


@pytest.fixture
def halmos_options(request):
    return request.config.getoption("--halmos-options")
