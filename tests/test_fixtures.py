import pytest

from halmos.__main__ import mk_solver
from halmos.config import default_config
from halmos.sevm import SEVM


@pytest.fixture
def args():
    return default_config()


@pytest.fixture
def sevm(args):
    return SEVM(args)


@pytest.fixture
def solver(args):
    return mk_solver(args)


@pytest.fixture
def halmos_options(request):
    return request.config.getoption("--halmos-options")
