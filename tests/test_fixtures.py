import pytest

from halmos.config import default_config
from halmos.sevm import SEVM
from halmos.__main__ import mk_options, mk_solver
import halmos.__main__


@pytest.fixture
def args():
    return default_config()


@pytest.fixture
def options(args):
    return mk_options(args)


@pytest.fixture
def sevm(options):
    return SEVM(options)


@pytest.fixture
def solver(args):
    return mk_solver(args)


@pytest.fixture
def halmos_options(request):
    return request.config.getoption("--halmos-options")
