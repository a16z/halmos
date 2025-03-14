import pytest

from halmos.__main__ import mk_solver
from halmos.calldata import FunctionInfo
from halmos.config import default_config
from halmos.sevm import SEVM


@pytest.fixture
def args():
    return default_config()


@pytest.fixture
def fun_info():
    return FunctionInfo("TestContract", "test", "test()", "f8a8fd6d")


@pytest.fixture
def sevm(args, fun_info):
    return SEVM(args, fun_info)


@pytest.fixture
def solver(args):
    return mk_solver(args)


@pytest.fixture
def halmos_options(request):
    return request.config.getoption("--halmos-options")
